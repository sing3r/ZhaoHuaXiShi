# Web Cache Poisoning: URL Discrepancies (路径解析差异)

## 0x01 核心逻辑 (The Core Inconsistency)

此类攻击的核心在于通过构造特殊的 URL，使得：

- **缓存服务器 (Cache)**：认为请求的是一个**静态资源**（如 `.js`, `.css`），从而决定缓存响应。
- **后端服务器 (Origin)**：通过解析分隔符或规范化，认为请求的是一个**动态页面**（如 `/home`, `/myAccount`），并返回包含用户数据的响应。

------

## 1. 分隔符利用 (Delimiters)

不同的框架和服务器对路径中“特殊字符”的定义不同，这会导致路径截断或参数解析差异。

| **分隔符**       | **典型环境**  | **后端解析行为**           | **示例 (攻击路径)**                      |
| ---------------- | ------------- | -------------------------- | ---------------------------------------- |
| **分号 `;`**     | Spring / Java | 视为矩阵变量，忽略其后内容 | `/home;/.js` $\rightarrow$ `/home`       |
| **点号 `.`**     | Ruby on Rails | 视为格式说明符             | `/account.css` $\rightarrow$ `/account`  |
| **空字节 `%00`** | OpenLiteSpeed | 截断路径                   | `/home%00.png` $\rightarrow$ `/home`     |
| **换行符 `%0a`** | Nginx         | 分隔 URL 组件              | `/user/home%0a.js` $\rightarrow$ `/home` |

------

## 0x02 规范化与编码 (Normalization & Encodings)

当路径中包含转义字符（如 `%2f`）或点号（`..`）时，差异往往出现在**谁先解码**。

### 2.1 编码不一致

- **场景**：攻击者请求 `/myAccount%3F.js`。
- **缓存层**：不解码 `%3F` (?)，认为文件名是 `myAccount%3F.js`，符合静态后缀，存入缓存。
- **源站层**：先解码 `%3F` 变成 `?`，认为请求是 `/myAccount` 带着参数 `.js`，返回个人中心页面。

### 2.2 点段 (Dot Segments)

- **路径穿越差异**：请求 `/static/..%2fhome`。
- **缓存层**：可能不解析 `%2f`，将其作为 Key 存储。
- **源站层**：解析为 `/static/../home`，最终指向 `/home`。

------

## 0x03 强制触发静态缓存 (Forcing Static Cache)

利用缓存策略中的“白名单”规则来诱导其缓存动态页面。

### 3.1 扩展名欺骗 (Extension Spoofing)

利用 CDN（如 Cloudflare）对特定后缀（7z, png, js, css 等）的自动缓存倾向。

- **Payload**: `/api/userInfo/..;/style.css`
- **结果**: 缓存服务器看到 `.css` 结尾决定缓存，而 Spring 后端因为 `;` 截断解析为 `/api/userInfo`。

### 3.2 知名静态目录 (Static Directories)

缓存服务器通常会配置 `/static/`, `/assets/`, `/wp-content/` 等目录为全量缓存。

- **技巧**：利用路径穿越尝试进入这些目录。
- **Payload**: `/home/..%2fstatic/image.png`
- **效果**: 缓存 Key 是 `/static/image.png`，但响应内容是 `/home`。

### 3.3 特定静态文件

一些文件如 `/robots.txt`, `/favicon.ico` 几乎总是被缓存。

- **Payload**: `/admin/..%2frobots.txt`

------

## 0x04 寻找差异的 Methodology (渗透测试步骤)

1. **探测分隔符**：
   - 在动态路径后添加随机字符：`/home/random` (返回 404)。
   - 在中间插入潜在分隔符：`/home;random` (若返回 200，说明 `;` 是分隔符)。
2. **验证编码解析**：
   - 尝试对 `/` (`%2f`), `?` (`%3f`), `#` (`%23`) 进行编码，观察 `X-Cache` 命中情况。
3. **对比静态资源响应**：
   - 找一个已知的静态资源，查看其 Header。
   - 尝试通过构造路径（利用分隔符）让动态页面返回相同的缓存 Header。

## 
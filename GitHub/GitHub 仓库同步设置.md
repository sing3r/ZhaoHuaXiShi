### 1. 核心操作流 (三部曲)

每当你写完新笔记，只需在终端依次输入：

- **`git pull`**： 同步 GitHub 云端笔记

- **`git add .`**：把新笔记放入“待发送清单”。
- **`git commit -m "备注内容"`**：给这次保存写个简短说明。
- **`git push`**：同步到 GitHub 云端。

### 2. 身份验证：告别“账号密码”

**重点：** GitHub 已经不支持在命令行直接输入网页登录密码。

- **推荐方案 (SSH)**：生成 SSH 密钥对，把公钥（`id_ed25519.pub`）贴到 GitHub 设置里。这样在 WSL 里推送时，系统会自动完成加密验证，无需手动输入任何内容。
- **备选方案 (Token)**：在 GitHub 生成 Personal Access Token，在提示输入密码时粘贴它。

### 3. 错误排查：处理 `fatal` 报错

针对你刚才遇到的 `is not a valid repository name`：

- **原因**：通常是本地 Git 记录的远程 URL 格式有误（可能有不可见字符或命名冲突）。
- **对策**：先用 `git remote remove origin` 删掉旧链接，再用 `git remote add origin [正确地址]` 重新绑定。

### 4. 环境建议 (WSL 用户专项)

- **命名规范**：虽然本地目录叫 `朝花夕拾` 很浪漫，但建议 **GitHub 上的仓库名使用英文或拼音**（如 `ZhaoHuaXiShi`），避免 Linux 路径编码带来的潜在 Bug。
- **主分支名**：现代 Git 默认分支名为 `main`，推送时请确认指令为 `git push -u origin main`。
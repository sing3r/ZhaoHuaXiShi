# ~~还是用 MarkText 吧!!!~~

---

# ~~0x01 下载 [Typora 1.10.8](https://downloads.typora.io/windows/typora-setup-x64-1.10.8.exe)~~

~~下载链接：[https://downloads.typora.io/windows/typora-setup-x64-1.10.8.exe](https://downloads.typora.io/windows/typora-setup-x64-1.10.8.exe)~~

# ~~0x02 破解~~

## ~~方案一：修改注册表突破使用试用时长~~

```powershell
# 获取当前注册时间
Get-ItemProperty -Path "HKCU:\Software\Typora" -Name "IDate"
# 修改当前注册时间
Set-ItemProperty -Path "HKCU:\Software\Typora" -Name "IDate" -Value "3/9/2099"
```

## ~~方案二：修改 **LicenseIndex** 文件~~

1. ~~找到 **`Typora\resources\page-dist\static\js\LicenseIndex.{id}.js`**~~ 

2. ~~修改 **`e.hasActivated="true"==e.hasActivated`** 为 **`e.hasActivated="true"=="true"`**~~

# ~~0x03 参考~~

~~[https://blog.csdn.net/qq_25828905/article/details/148843115](https://blog.csdn.net/qq_25828905/article/details/148843115)~~

~~[https://www.cnblogs.com/jerrycyx/p/archive/2025/05/26](https://www.cnblogs.com/jerrycyx/p/archive/2025/05/26)~~

# 0x01 下载任意版本的 Typaro

下载链接：[https://typora.io/#download](https://typora.io/#download)

# 0x02 无限试用

- powershell 脚本

```powershell
# 1. 定义目标路径
$regPath = "HKCU:\Software\Typora"

# 2. 获取当前 ACL
$acl = Get-Acl -Path $regPath

# 3. 定义需要拒绝的对象
# 目标 A: 当前用户
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
# 目标 B: 管理员组 (SID 为 S-1-5-32-544 是 Windows 固定的管理员组标识)
$adminGroup = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$adminGroupName = $adminGroup.Translate([System.Security.Principal.NTAccount]).Value

# 4. 创建拒绝规则函数
function Create-DenyRule($identity) {
    return New-Object System.Security.AccessControl.RegistryAccessRule(
        $identity,
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Deny"
    )
}

# 5. 应用规则
$acl.SetAccessRule((Create-DenyRule $user))
$acl.SetAccessRule((Create-DenyRule $adminGroupName))

# 6. 将 ACL 写回注册表
Set-Acl -Path $regPath -AclObject $acl

Write-Host "已成功对用户 [$user] 和组 [$adminGroupName] 拒绝了完全控制权限。" -ForegroundColor Red
```

- 恢复脚本

```powershell
$regPath = "HKCU:\Software\Typora"
$acl = Get-Acl -Path $regPath

# 移除所有的 Deny 规则
$rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
foreach ($rule in $rules) {
    if ($rule.AccessControlType -eq "Deny") {
        $acl.RemoveAccessRule($rule)
    }
}

Set-Acl -Path $regPath -AclObject $acl
Write-Host "所有拒绝规则已移除，权限已恢复正常。" -ForegroundColor Green
```

# 0x03 参考

- https://juejin.cn/post/7250268273638948925

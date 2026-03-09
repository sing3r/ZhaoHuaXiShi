# 0x01 下载 [Typora 1.10.8](https://downloads.typora.io/windows/typora-setup-x64-1.10.8.exe) 

下载链接：[https://downloads.typora.io/windows/typora-setup-x64-1.10.8.exe](https://downloads.typora.io/windows/typora-setup-x64-1.10.8.exe)

---

# 0x02 破解

## 方案一：修改注册表突破使用试用时长

```powershell
# 获取当前注册时间
Get-ItemProperty -Path "HKCU:\Software\Typora" -Name "IDate"
# 修改当前注册时间
Set-ItemProperty -Path "HKCU:\Software\Typora" -Name "IDate" -Value "3/9/2099"
```

## 方案二：修改 **LicenseIndex** 文件

1. 找到 **`Typora\resources\page-dist\static\js\LicenseIndex.{id}.js`** 

2. 修改 **`e.hasActivated="true"==e.hasActivated`** 为 **`e.hasActivated="true"=="true"`**

- **背景**：Nessus专业版价格高昂，本文提供个人测试用的破解方法，以Windows 10.11.1-x64版本为例。

- **关键流程**：
  1. **安装与初始配置**：官网下载安装包，安装时选择“Register Offline”，设置管理员账号，并指定为“Managed Scanner”模式。
  
  2. **插件包获取**：
     
     - 停止Nessus服务，获取`Challenge code`；
     
     - 注册[官网](https://www.tenable.com/products/nessus/nessus-essentials)账号获取`Activation Code`，可以使用临时邮箱注册；
     
     - 通过官方插件页面下载插件包（`all-2.0.tar.gz`）和许可文件（`nessus.license`）；
     
     - 执行离线注册与插件更新命令。
     
       ```
       nessuscli.exe fetch --register-offline "\pathto\nessus.license"
       nessuscli.exe update \pathto\all-2.0.tar.gz
       ```
     
  3. **破解操作**：
     
     - 修改`plugin_feed_info.inc`文件，覆盖`PLUGIN_SET`为生成的版本号；
     
       ```
       PLUGIN_SET = "覆盖位置";
       PLUGIN_FEED = "ProfessionalFeed (Direct)";
       PLUGIN_FEED_TRANSPORT = "Tenable Network Security Lightning";
       ```
     
     - 将修改后的`plugin_feed_info.inc`文件覆盖其他`plugin_feed_info.inc`
     
     - 将调整文件属性（隐藏/只读）；
     
       ```
       attrib +s +r +h "C:\ProgramData\Tenable\Nessus\nessus\plugins\*.*"
       attrib +s +r +h "C:\ProgramData\Tenable\Nessus\nessus\plugin_feed_info.inc"
       attrib -s -r -h "C:\ProgramData\Tenable\Nessus\nessus\plugins\plugin_feed_info.inc"
       ```
     
     - 重启服务，等待插件编译完成即可登录使用。
  
- **注意事项**：需显示系统隐藏文件，部分命令执行时间长，且破解后需关闭自动更新以防失效。


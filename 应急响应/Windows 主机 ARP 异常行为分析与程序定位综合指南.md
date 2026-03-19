# Windows 主机 ARP 异常行为分析与程序定位综合指南

## 1. 现象与背景

**行为特征：**

主机对自身所在网段（如 `10.1.10.0/24`）发起高频 ARP 请求（`Who has 10.1.10.x?`）。

- **频率：** 每秒约 5-9 次请求。
- **模式：** 按 IP 顺序（.1 至 .254）循环扫描或随机跳跃扫描。
- **归属特征：** Wireshark 中发包进程常标记为 `System (PID 4)`。

**潜在危害：**

ARP Flood、ARP Spoof/欺骗、中间人攻击（MITM）、网关劫持、网络拥塞。

**核心目标：**

快速定位究竟是哪一个程序在发送 ARP 数据包，并**通过分析其伴随的网络行为，判断其意图与威胁等级**。

## 2. 总体排查思路与流程

**核心思路：** `网络行为 → 进程 → 程序路径 → 行为链分析`

**标准应急响应流程：**

```
1. 确认ARP攻击特征及是否来自本机
   ↓
2. 抓取网络事件，关联进程ID (PID)
   ↓
3. 分析伴随网络行为（关键步骤）
   ↓
4. 定位可疑进程及程序路径
   ↓
5. 综合判断攻击模式与威胁
```

**最快定位方法（安全工程师常用）：**

1. **命令行快速筛查：** 执行 `tasklist /m npcap.dll` 或 `tasklist /m wpcap.dll`。
2. **句柄检查：** 使用 `handle npf` 或 `handle \Device\NPF` 命令。
3. **进程监控：** 使用 Process Monitor 过滤 `Path contains \Device\NPF`。

## 3. 溯源分析五阶段流程

### 阶段一：邻居表与接口判定（初筛）

判断行为是否走标准协议栈，锁定物理/虚拟接口。

- **排查命令：** 

```powershell
# 检查邻居表状态
Get-NetNeighbor | Where-Object { $_.State -ne "Permanent" } | Sort-Object State
# 根据异常条目的 ifIndex 识别网卡
Get-NetAdapter | Where-Object { $_.ifIndex -eq [对应Index] }
```

- 判定依据：
  - **现象：** 大量 IP 状态为 `Unreachable`，MAC 为 `00-00-00-00-00-00`。
  - **结论：** 标准 API 调用。若 `ifIndex` 指向物理网卡，查宿主机程序；若指向虚拟网卡（WSL/VMware/VPN），查子系统或隧道逻辑。

### 阶段二：应用层指纹定位（针对标准程序/脚本）

利用标准网络库调用时必经的注册表访问行为进行实时进程锁定。

- **工具：** Process Monitor (ProcMon)
- 核心过滤规则：
  - `Path - contains - Tcpip\Parameters`
  - `Operation - is - RegQueryValue`
  - **重点键值：** `Hostname` / `Domain`
- **判定逻辑：** 寻找与 ARP 包发送频率完全同步的进程（如 `powershell.exe`）。

### **阶段三：关联连接行为审计（关键：区分恶意扫描与攻击）**

**核心思想：ARP异常往往是更大规模网络活动的“前奏”。分析其伴随行为是判断威胁意图的关键。**

- **排查命令（寻找半开连接）：** 

```powershell
Get-NetTCPConnection | Where-Object { $_.State -eq "SynSent" } | Select-Object LocalAddress, RemoteAddress, RemotePort, OwningProcess
```

- 工具辅助：
  - **TCPView：** 直观查看所有TCP/UDP连接及对应进程。
  - **ProcMon：** 过滤 `TCP Connect` 或 `UDP Send` 操作，关联进程。
- 关键判定与威胁分析：
  - **模式A（管理/误报）：** 仅有ARP扫描，无后续连接或仅有少量ICMP。邻居表有`Unreachable`记录。**可能元凶：** 网络发现脚本、打印机服务、SMB自动发现。
  - **模式B（恶意横向移动）：** **ARP扫描 + 针对高危端口的TCP SYN扫描**（如445/SMB, 135/RPC, 3389/RDP, 22/SSH）。**这是勒索软件、蠕虫、内网渗透工具的典型指纹。** 发现此类行为应**立即隔离主机**。
  - **模式C（中间人攻击准备）：** ARP扫描模式为**欺骗性Reply**（伪造`is-at`响应），旨在毒化ARP表。**可能伴随：** SSL剥离或流量嗅探工具（如`ettercap.exe`, `bettercap.exe`）。
  - **模式D（全面侦察）：** ARP扫描后伴随对大量不同端口（80/443/8080/数据库端口等）的探测。**可能元凶：** 内网渗透扫描器、高级持续性威胁（APT）工具。

### 阶段四：底层驱动与句柄深度排查（绕过协议栈）

若邻居表异常“干净”，说明程序绕过了协议栈，直接操作网卡驱动。

- 方法A：核心库与句柄搜索 (System Informer)
  - **DLL 搜索：** `packet.dll`, `wpcap.dll`, `npcap.dll`, `winpcap.dll`, `ndistapi.dll`。
  - **句柄搜索：** `\Device\Ndis`、`\Device\Packet`、`\Device\Npcap`、`\Device\WPF`。
- 方法B：启动项与驱动审计 (Autoruns)
  - **操作：** `Drivers` 选项卡 + `Hide Microsoft Entries`。
  - **重点厂商：** 火绒 (`sysdiag.sys`)、360、Insecure.Com (Npcap)。

### 阶段五：I/O 行为关联（针对驱动发包程序）

若网络发送速率无法稳定捕捉，转向 I/O 计数器。

- **排查工具：** System Informer / 任务管理器（需开启“I/O 写入”列）。
- **监控指标：** `I/O Write Rate` (或 `I/O Write Bytes`)。
- **判定逻辑：** 在无明显文件写入的情况下，`I/O Write Rate` 持续波动，且波动频率与 ARP 发包一致，表明程序正频繁地将原始封包数据写入 NDIS/Npcap 驱动接口。

## 4. 关键工具与操作速查

### 4.1 确认攻击与来源

- Wireshark/tcpdump 抓包：
  - **基础过滤：** `arp`
  - **增强过滤（行为链分析）：** `(arp) or (tcp.flags.syn == 1 and tcp.flags.ack == 0) or (udp) or (dns)` 进行全景观察。
  - **Flood 特征：** `Who has 192.168.1.1? Tell 192.168.1.X` 大量刷屏。
  - **Spoof 特征：** `192.168.1.1 is-at XX:XX:XX:XX` 来源 MAC 不一致。
  - **判断本机发送：** 过滤 `arp && eth.src == 本机MAC`。

### 4.2 进程级定位

- System Informer：
  - 查看 `Processes` → `Network` 列，按 `Send Rate` 排序，观察高发送进程。
- Process Explorer (Sysinternals)：
  - `View` → `Lower Pane` → `DLL`，搜索进程是否加载 `npcap.dll`、`wpcap.dll`、`packet.dll`。
- 火绒剑：
  - `系统分析` → `进程`，查看 `网络连接` 或 `句柄`，重点查找 `\Device\NPF_`。

### 4.3 系统级追踪（高级）

- **Windows 内置工具** **`pktmon`：** 

```cmd
pktmon filter remove
pktmon filter add MyARP -d 0x0806  # 0x0806 为 ARP 协议号
pktmon start --etw
pktmon stop
pktmon format pktmon.etl -o pktmon.txt
```

- **ETW 网络事件追踪：** 

```cmd
netsh trace start scenario=NetConnection capture=yes report=no persistent=no maxsize=512 tracefile=.\arp_trace.etl
netsh trace stop
```

- **分析工具：** Windows Performance Analyzer (WPA)，查看 `Microsoft-Windows-NDIS-PacketCapture` 提供程序，筛选 `08 06` (ARP) 及 `Process Id`。

## 5. 常见异常对照与威胁判定

| 扫描模式          | 典型指纹                             | **关键伴随行为**                             | 威胁等级  | 可能的元凶                                       |
| ----------------- | ------------------------------------ | -------------------------------------------- | --------- | ------------------------------------------------ |
| **标准 API 模式** | 邻居表 `Unreachable` + 注册表访问    | 无或极少（仅ICMP）                           | **低**    | 管理脚本、网络打印机、SMB 自动发现               |
| **恶意横向移动**  | 邻居表 `Unreachable` + TCP `SynSent` | **大量针对445/135/3389等高危端口的连接尝试** | **极高**  | 勒索病毒、蠕虫、内网渗透工具                     |
| **底层驱动模式**  | 邻居表无记录 + NDIS 句柄持有         | 通常为单一驱动行为，或伴随自定义协议的流量   | **中-高** | 安全软件防护扫描、资产管理 Agent、定制化攻击工具 |
| **虚拟化/隧道**   | `ifIndex` 指向虚拟/VPN 接口          | 协议心跳、网桥探测或隧道保活流量             | **低**    | WSL2、VPN 客户端、Docker、VMware NAT             |

**常见 ARP 攻击工具进程：** `arpspoof.exe`, `ettercap.exe`, `bettercap.exe`, `nmap.exe`, `masscan.exe`, `python.exe` (使用 Scapy)。

## 6. 实战增强：结合伴随行为的排查步骤

1. **全景抓包，建立时间线：** 使用Wireshark持续抓包，观察ARP请求后是否立即出现对**相同目标IP**的TCP SYN包或其他协议流量。
2. **系统状态快照关联：** 在抓包同时，迅速执行 `netstat -ano` 或 `Get-NetTCPConnection`，寻找 `SYN_SENT` 状态的连接，并记录其PID。
3. **进程深度剖析：** 使用 **Process Monitor** 对可疑PID设置过滤器，监控其**网络、文件、注册表、进程**全方位操作，构建完整攻击链视图。
4. 威胁研判与处置：
   - 若确认为**模式B（恶意横向移动）**，立即进行网络隔离，并按照恶意软件处置流程进行清除和溯源。
   - 若确认为**模式C（中间人攻击）**，需全网检查ARP表是否被毒化，并排查可能的嗅探节点。
   - 若为其他模式，根据业务情况决定是放行、优化还是终止相关进程。

## 7. 补充建议

1. **开启系统内核审计：** 如果工具无法直接定位，可开启 Windows 过滤平台 (WFP) 审计日志。

   ```powershell
    auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable 
   ```

   开启后，在事件查看器中检索事件 ID `5156` (允许连接)。

2. **分析技巧：** 使用 Process Monitor 监控线程活动时，双击网络操作条目查看 `Stack` (堆栈)。如果堆栈中出现 `iphlpapi.dll!SendARP` 或 `ws2_32.dll` 的调用，则该进程很可能是源头。

   ---

**总结：本指南强调将ARP异常视为一个“警报触发器”。通过系统性地分析其伴随的网络行为链，安全人员不仅能精准定位攻击程序，更能直接判断攻击者的意图、阶段和威胁等级，从而实现从被动响应到主动研判的升级。**
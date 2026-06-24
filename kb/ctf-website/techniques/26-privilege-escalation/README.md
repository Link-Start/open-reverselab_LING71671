# 26-privilege-escalation — 权限提升技术

## 文档索引

| 文件 | 内容 | 难度 |
|------|------|------|
| [00-overview.md](00-overview.md) | PE 全景与决策树 | 入门 |
| [01-linux-sudo-suid.md](01-linux-sudo-suid.md) | SUDO 滥用 + SUID/SGID + Capabilities + PATH | 基础→进阶 |
| [02-linux-cron-service.md](02-linux-cron-service.md) | Cron/服务/通配符注入/NFS/库劫持 | 进阶 |
| [03-linux-kernel-cve.md](03-linux-kernel-cve.md) | Linux 内核 CVE 利用方法论 | 高阶 |
| [04-windows-pe.md](04-windows-pe.md) | Windows 提权方法论 | 进阶 |
| [05-container-escape.md](05-container-escape.md) | 容器逃逸快速手册 | 进阶→高阶 |

## 快速入口

- 刚拿到 shell 不知道怎么提权 → [00-overview.md](00-overview.md)
- sudo -l 有输出 → [01-linux-sudo-suid.md](01-linux-sudo-suid.md)
- 发现 SUID 二进制 → [01-linux-sudo-suid.md](01-linux-sudo-suid.md)
- 有可写 cron/脚本 → [02-linux-cron-service.md](02-linux-cron-service.md)
- 内核老 → [03-linux-kernel-cve.md](03-linux-kernel-cve.md)
- Windows 机器 → [04-windows-pe.md](04-windows-pe.md)
- 在容器里 → [05-container-escape.md](05-container-escape.md)

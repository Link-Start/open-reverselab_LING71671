# RCE Attack Surface — 远程代码执行攻击全景与决策树

> 代码执行是 Web 攻击的最终目标。无论入口是注入、上传、反序列化还是文件包含，落地为可交互 shell 的技术障碍是共通的。本指南提供从漏洞到 shell 的系统化决策路径。

## 关键词

`RCE` `命令执行` `代码执行` `shell` `webshell` `反弹shell` `reverse shell` `disable_functions` `open_basedir` `免杀` `命令注入` `command injection` `INTO OUTFILE` `php://input` `log poisoning` `LD_PRELOAD` `FFI` `UAF` `不出网` `WAF绕过`

## 攻击面全景

```
RCE 攻击面:
┌──────────────────────────────────────────────────────────────┐
│  直接执行层                                                   │
│  ├─ OS 命令注入 (; | ` $() 换行 注入)                         │
│  ├─ 代码注入 (eval/assert/preg_replace /e/create_function)    │
│  ├─ SSTI → RCE (Jinja2/Twig/Freemarker 沙箱逃逸)              │
│  └─ 表达式注入 (SpEL/OGNL/MVEL/EL)                            │
├──────────────────────────────────────────────────────────────┤
│  文件写入层                                                    │
│  ├─ 文件上传 → webshell (扩展名/Content-Type/图片马绕过)       │
│  ├─ SQL INTO OUTFILE/DUMPFILE → webshell                      │
│  ├─ LFI + php://input/data:// → 代码执行                      │
│  ├─ LFI + 日志污染 (/var/log/apache2/access.log)              │
│  ├─ LFI + session 文件污染 (PHP_SESSION_UPLOAD_PROGRESS)      │
│  └─ 备份恢复/导入 → webshell                                  │
├──────────────────────────────────────────────────────────────┤
│  反序列化层                                                    │
│  ├─ PHP unserialize() → gadget chain → RCE                    │
│  ├─ Python pickle → __reduce__ → RCE                          │
│  ├─ Java readObject() → gadget chain → RCE                    │
│  ├─ Node.js node-serialize → IIFE → RCE                       │
│  └─ PHAR 反序列化 (phar:// 伪协议)                             │
├──────────────────────────────────────────────────────────────┤
│  间接执行层                                                    │
│  ├─ SSRF → 内网 RCE 服务 (Redis/Gopher/docker API)            │
│  ├─ XXE → expect:// 协议 → 命令执行                            │
│  ├─ 数据库 UDF 提权 (MySQL plugin / PostgreSQL C extension)    │
│  └─ CI/CD 流水线注入 → 构建脚本执行                            │
└──────────────────────────────────────────────────────────────┘
```

## 文档索引

| 文档 | 内容 | 难度 |
|------|------|------|
| [01-command-injection.md](01-command-injection.md) | OS 命令注入：操作符、盲打、绕过、参数注入 | 基础→进阶 |
| [02-webshell.md](02-webshell.md) | Webshell：形态、免杀、WAF 绕过、无文件 | 进阶 |
| [03-php-disable-functions-bypass.md](03-php-disable-functions-bypass.md) | PHP 函数禁用绕过：LD_PRELOAD/FFI/UAF/imap_open | 高阶 |
| [04-reverse-shell-bind.md](04-reverse-shell-bind.md) | 反弹/绑定 Shell：协议、隧道、不出网突破 | 进阶 |
| [05-chain-playbook.md](05-chain-playbook.md) | 漏洞链串接：文件读取→shell、注入→shell 等 | 高阶 |

## 核心决策树

```
发现代码执行可能:
├─ 直接命令/代码注入点
│  ├─ 有回显 → 直接执行 whoami/id, 确认后选 shell 类型
│  │  ├─ 出网 → [04] 反弹 shell
│  │  ├─ 入网 → [04] 绑定 shell
│  │  └─ 都不通 → [02] 写 webshell
│  └─ 无回显 (blind) → [01] OOB 验证 (dns/curl/icmp)
│
├─ 文件上传点
│  ├─ 直接上传 PHP/ASPX/JSP → [02] webshell 免杀
│  ├─ 扩展名过滤 → [02] 绕过字典 (.phtml/.phar/.php5...)
│  ├─ 内容检查 → [02] 图片马/EXIF 嵌入
│  └─ 仅允许图片 → LFI 包含上传文件 or phar:// 反序列化
│
├─ SQL 注入
│  ├─ MySQL root/file_priv → [05] INTO OUTFILE 写 webshell
│  ├─ PostgreSQL → COPY TO PROGRAM / lo_export
│  ├─ MSSQL → xp_cmdshell / sp_OACreate
│  └─ Oracle → DBMS_SCHEDULER / Java stored procedure
│
├─ LFI/RFI
│  ├─ php://input → POST code = RCE
│  ├─ data:// → data://text/plain,<?php system('id');?>
│  ├─ 日志污染 → User-Agent 注入 PHP → 包含 access.log
│  └─ /proc/self/environ → 注入 HTTP 头 → 包含
│
├─ SSTI / 表达式注入
│  └─ 沙箱逃逸 → 获得 os.popen/subprocess → [04] 反弹 shell
│
├─ 反序列化
│  └─ gadget chain → 命令执行 → [04] 选 shell 类型
│
└─ SSRF
   ├─ gopher:// 协议 → Redis/Memcached/MySQL → webshell/cron
   ├─ dict:// 协议 → 端口探测
   └─ file:// 协议 → 读取源码 → 发现新攻击面
```

## Shell 选型矩阵

| 网络条件 | 推荐方案 | 优点 | 缺点 |
|---------|---------|------|------|
| 出网 (egress) | 反弹 shell (bash/python/php) | 稳定、加密可选 | 需监听端 |
| 入网 (ingress) | 绑定 shell (nc/socat) | 被动接入 | 防火墙常拦 |
| 都不通 | Webshell (一句话) | HTTP 通道必定通 | 功能受限,需 bypass |
| HTTP only (无 TCP) | Webshell + 文件管理/数据库隧道 | 仅需 Web 端口 | 交互差 |
| DNS only | DNS tunnel (dnscat2/iodine) | 极窄通道 | 慢 |

## 环境约束分层

```
Shell 成功率 = 漏洞原语 × (1 - 环境限制)

环境限制层级:
L1: WAF/CDN 拦截 payload → 编码/分块/混淆绕过
L2: disable_functions 限制 → LD_PRELOAD/FFI/UAF 突围
L3: open_basedir 限制 → 目录跳跃/symlink 绕过
L4: 不出网 (防火墙出站规则) → DNS/ICMP tunnel 或 webshell
L5: 非交互 shell (webshell) → 升级为伪终端
L6: 容器/沙箱 → 逃逸 (另行参考 Kubernetes 章节)
```

## 关联技术

- [[file-upload-xxe-lfi]] — 文件上传/XXE/LFI
- [[ssti]] — SSTI 沙箱逃逸
- [[deserialization]] — 反序列化漏洞
- [[01-sqli-fundamentals]] — SQL 注入文件读写
- [[ssrf]] — SSRF → RCE
- [[kubernetes-container]] — 容器逃逸

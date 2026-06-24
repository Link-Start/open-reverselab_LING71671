# 25-rce-shell — 远程代码执行与 Shell 获取

## 文档索引

| 文件 | 内容 | 难度 |
|------|------|------|
| [00-overview.md](00-overview.md) | RCE 攻击全景与决策树 | 入门 |
| [01-command-injection.md](01-command-injection.md) | OS 命令注入深度方法论 | 基础→进阶 |
| [02-webshell.md](02-webshell.md) | Webshell 形态、免杀、WAF 绕过 | 进阶 |
| [03-php-disable-functions-bypass.md](03-php-disable-functions-bypass.md) | PHP disable_functions 绕过全集 | 高阶 |
| [04-reverse-shell-bind.md](04-reverse-shell-bind.md) | 反弹/绑定 Shell 与隧道突破 | 进阶 |
| [05-chain-playbook.md](05-chain-playbook.md) | 漏洞→Shell 串接方法论 | 高阶 |

## 快速入口

- 不确定自己的漏洞怎么用 → [00-overview.md](00-overview.md)
- 找到了命令拼接点但被过滤 → [01-command-injection.md](01-command-injection.md)
- 想上传 webshell 却被 WAF 拦 → [02-webshell.md](02-webshell.md)
- 拿到 webshell 但 system() 不可用 → [03-php-disable-functions-bypass.md](03-php-disable-functions-bypass.md)
- 需要反弹 shell 但不出网 → [04-reverse-shell-bind.md](04-reverse-shell-bind.md)
- 如何从文件读取一路打穿到 shell → [05-chain-playbook.md](05-chain-playbook.md)

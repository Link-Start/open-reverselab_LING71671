# Web Attack Network

Web CTF / 渗透测试攻击路径全景图。每个节点是一个攻击技术方向，边表示路径依赖和组合关系。

## 入口点

```
[目标 URL]
    │
    ├── Recon ───────────────────────────────────────┐
    │   ├── 端口扫描 (nmap)                            │
    │   ├── 目录爆破 (dirsearch/ffuf/gobuster)         │
    │   ├── 指纹识别 → 版本/框架/CMS                   │
    │   └── JS 源码分析 (JSHook)                       │
    │                                                  │
    ├── Auth ────────────────────────────────────────┤
    │   ├── JWT 攻击链 (01-alg-none → 07-theft-replay)│
    │   ├── OAuth/SSO 绕过                             │
    │   ├── SAML 注入                                  │
    │   └── LDAP 注入                                  │
    │                                                  │
    ├── Injection ───────────────────────────────────┤
    │   ├── SQLi / NoSQLi                              │
    │   ├── SSTI (模板注入)                             │
    │   ├── GraphQL 注入                               │
    │   ├── gRPC/Protobuf                              │
    │   ├── HPP / CRLF                                 │
    │   └── Prototype Pollution                         │
    │                                                  │
    ├── SSRF ────────────────────────────────────────┤
    │   ├── SSRF → 内网探测                             │
    │   └── Open Redirect → SSRF 链                     │
    │                                                  │
    ├── File Attacks ────────────────────────────────┤
    │   ├── File Upload → RCE                          │
    │   ├── LFI / RFI                                  │
    │   └── XXE                                        │
    │                                                  │
    ├── Deserialization ─────────────────────────────┤
    │   ├── PHP unserialize                            │
    │   ├── Java deserialization                       │
    │   ├── Python pickle                              │
    │   └── Node.js node-serialize                     │
    │                                                  │
    ├── Client Side ─────────────────────────────────┤
    │   ├── XSS (Stored/Reflected/DOM)                 │
    │   ├── CSRF                                       │
    │   ├── CORS 配置错误                               │
    │   ├── PostMessage 滥用                            │
    │   └── WebSocket 劫持                              │
    │                                                  │
    ├── Infra ───────────────────────────────────────┤
    │   ├── HTTP Request Smuggling                     │
    │   ├── Cache Poisoning / Deception                │
    │   ├── Race Condition (Turbo Intruder)            │
    │   └── HTTP/2 攻击                                │
    │                                                  │
    ├── CVE Chain ───────────────────────────────────┤
    │   ├── 版本指纹 → CVE 查询 → multi-CVE 链         │
    │   └── 多产品组合 CVE                              │
    │                                                  │
    ├── Cloud ───────────────────────────────────────┤
    │   ├── Serverless / Lambda                        │
    │   ├── Kubernetes                                  │
    │   └── CI/CD Pipeline                              │
    │                                                  │
    ├── Supply Chain ────────────────────────────────┤
    │   └── Dependency Confusion / Typosquatting        │
    │                                                  │
    └── Payment ─────────────────────────────────────┤
        ├── 支付逻辑绕过                                │
        ├── 金额篡改                                    │
        ├── 回调异步利用                                │
        └── 订阅/数字商品                               │
```

## 使用方式

1. 每发现一个信号（JWT、SQLi、SSRF...），沿攻击网找到对应节点
2. 读取 `kb/ctf-website/techniques/<编号>-<类别>/` 下的技术文件
3. 技术文件中有可运行的伪代码，直接复制、修改 URL、执行
4. 不要只走一条链 — 从不同入口点并行探测

## 编号体系

| 编号 | 类别 | 目录 |
|---|---|---|
| 01 | Recon | `01-recon/` |
| 02 | Auth | `02-auth/` |
| 03 | Injection | `03-injection/` |
| 04 | SSRF | `04-ssrf/` |
| 05 | Deserialization | `05-deserialization/` |
| 06 | File Attacks | `06-file-attacks/` |
| 07 | Client Side | `07-client/` |
| 08 | Infra | `08-infra/` |
| 09 | CVE | `09-cve/` |
| 10 | Cloud | `10-cloud/` |
| 11 | Supply Chain | `11-supply-chain/` |
| 12 | Payment | `12-payment/` |
| 13 | Signature | `13-signature/` |

## 工具路由

每类攻击对应的首选工具见 `kb/ctf-website/techniques/kb-index.json`，或运行：

```bash
python scripts/ctf-website/kb_router.py "<信号关键词>"
```

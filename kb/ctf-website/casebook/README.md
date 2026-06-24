# CTF 案例手册

> 所有实战案例的归档、模式提取和跨案例经验索引。
> 每个案例的 details 在 `cases/<date>-<slug>/` 目录。

## 案例矩阵

| # | 案例 | 类型 | 成果 | 关键漏洞/技术 |
|---|------|------|------|-------------|
| 1 | beigpt | 支付CTF | 完整API地图 + Epay签名逆向 | CAPTCHA绕过、Shared API认证绕过、runtime.log泄露 |
| 2 | dimosky | 授权审计 | **7个漏洞确认** | 未认证IDOR暴18000+订单+卡密 |
| 3 | lo2o65 | 支付CTF | **完整数据库提取** | 未认证IDOR /ajax.php?act=query 暴全部订单 |
| 4 | hanfolk-ai | 支付CTF | 支付链路完整分析 | Epay key爆破、余额参数fuzzing |
| 5 | darksec | Web CTF | API链还原 | Flask session伪造、converter竞态 |
| 6 | ksjer | CMS渗透 | XYCMS登录绕过 | PHP数组注入、5个exploit脚本 |
| 7 | hungrym0 | 资产侦察 | 完整资产树+70+子域名 | crt.sh枚举、UptimeKuma CVE PoC |
| 8 | tg5288-payment-ctf | 支付CTF | 完整支付链路还原 | CF Turnstile绕过、JS API提取 |
| 9 | bw2026-ticket-reverse | 抢票逆向 | 初始化 | JSHook JS参数逆向 |
| 10 | codex-batch-flag | 自动化 | 初始化 | SSO OAuth批量注册 |
| 11 | cve-pipeline-smoke | 管道测试 | 管道验证通过 | GeoServer指纹→CVE图 |
| 12 | nuist-jingsai | 模板 | 空 | - |
| 13 | zzshu-kawang | Web CTF | 初始化 | - |

## 跨案例模式

### 模式1: 未认证IDOR暴订单（3/13案例）

**dimosky**: `POST /user/api/index/query` → 18000+ 订单，含Google兑换链接、Outlook密码
**lo2o65**: `POST /ajax.php?act=query` → 全部订单，含明文卡密
**beigpt**: `POST /user/api/index/query` → 订单可查询（同框架acg-faka）

**共同特征**:
- PHP自建商城，`/user/api/index/query` 或 `/ajax.php?act=query`
- POST请求，参数通常是 `type=qq` 或 `keywords=` 或 `page=1&limit=100`
- 返回JSON含 `tradeNo`, `card_info`, `secret`, `contact`
- **都不需要登录！**

**通用攻击脚本**: 见 `../toolkit/idor_order_scanner.py`

### 模式2: 支付签名绕过（4/13案例）

**beigpt / dimosky / hanfolk-ai / tg5288** 全部对接 Epay/易支付/Codepay

**共同特征**:
- MD5签名: `md5(params + key)`
- sign_type 可指定或默认为MD5
- 签名密钥硬编码在 `Config.php`（acg-faka）或plugin目录下
- notify_url 通常为 `/plugin/epay/notify` 或 `/plugin/codepay/notify`

**通用攻击脚本**: 见 `../toolkit/epay_sign_bypass.py`

### 模式3: 邮箱域名白名单（2/13案例）

**tg5288 / beigpt** 都限制了可注册的邮箱域名

**接受**: gmail.com, outlook.com, qq.com, 163.com, 126.com, sina.com, yahoo.com, icloud.com
**拒绝**: 所有临时邮箱域名

**通用测试脚本**: 见 `../toolkit/email_domain_tester.py`

### 模式4: Cloudflare绕过（4/13案例）

**tg5288 / dimosky / hanfolk-ai / hungrym0** 都有Cloudflare

- Turnstile "managed" challenge 需要 Playwright 真实浏览器
- 同一browser session内的fetch不会重触发
- admin路径可能有额外WAF规则

**通用绕过脚本**: 见 `../toolkit/cloudflare_bypass.py`

## PHP发卡平台指纹速查

| 平台 | 版本标记 | 关键路径 | 支付插件 |
|------|---------|---------|---------|
| acg-faka | v=3.4.x | `/assets/common/js/ready.js`, `acg.js` | Epay/Codepay/Kvmpay |
| dujiaoka | - | Laravel路由, `/api/` | Epay/Paypal/Stripe |
| Annie Mall | v1030 | `/ajax.php?act=query` | 内置 |
| XYCMS | V10.1 | SeaCMS衍生 | - |

## 通用攻击流程（详见 checklists/）

```
Phase 1: Recon (30min)
  CF绕过 → JS全量抓取 → API提取 → 指纹识别

Phase 2: Auth (30min)
  邮箱探测 → 注册/登录 → Session分析 → 权限边界

Phase 3: Payment (60min)
  商品列表 → 下单流程 → 支付方式枚举 → 回调分析

Phase 4: Exploit
  IDOR订单遍历 → 签名绕过 → 回调伪造 → 余额/价格篡改
```

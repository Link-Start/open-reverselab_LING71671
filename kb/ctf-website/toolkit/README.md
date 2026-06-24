# CTF Toolkit — 可复用攻击脚本库

> 从 14 个实战案例中提取的通用脚本。每个脚本都有 CLI，独立可运行。

## 工具清单

| 脚本 | 用途 | 来源案例 |
|------|------|---------|
| `captcha_solver.py` | ddddocr验证码自动识别（URL/文件/base64） | beigpt, tg5288 |
| `idor_order_scanner.py` | 未认证订单IDOR批量扫描（Python版） | dimosky, lo2o65, beigpt |
| `idor_order_scanner.go` | 未认证订单IDOR批量扫描（Go版，200并发，三层并行） | dimosky, lo2o65, beigpt |
| `idor_scan.exe` | Go编译好的Windows二进制（开箱即用） | 所有案例 |
| `email_domain_tester.py` | 邮箱域名白名单批量探测（60+域名预制） | tg5288, beigpt |
| `api_auth_scanner.py` | API认证边界扫描（支付CTF预设端点） | 全部案例 |
| `js_api_extractor.py` | 前端JS全量抓取 + API端点正则提取 | 全部案例 |
| `cloudflare_bypass.py` | Playwright Turnstile绕过 + Cookie持久化 | tg5288, dimosky, hanfolk-ai |
| `epay_sign_bypass.py` | 易支付/Epay签名绕过矩阵 | beigpt, dimosky, hanfolk-ai |

## 快速开始

```bash
# 安装依赖
pip install ddddocr requests Pillow playwright
playwright install chromium

# 场景1: 新支付CTF目标，一键侦察
python api_auth_scanner.py --url https://target --preset payment
python email_domain_tester.py --url https://target
python idor_order_scanner.py --url https://target --framework all

# 场景2: 遇到验证码
python captcha_solver.py --url https://target/user/captcha/image?action=trade

# 场景3: Cloudflare挡路
python cloudflare_bypass.py --url https://target --save-cookies cf_cookies.json
```

## 典型攻击链

```
python api_auth_scanner.py --url $TARGET --preset payment -o recon.json
  → 发现 open endpoints

python idor_order_scanner.py --url $TARGET --framework all
  → 如果命中IDOR，直接拿flag

python email_domain_tester.py --url $TARGET
  → 确定可用邮箱域名 → 注册 → 登录 → 下单

python captcha_solver.py --url "$TARGET/user/captcha/image?action=trade"
  → 自动化验证码 → 批量测试支付参数
```

## 添加新框架预设

在对应脚本的 `PRESETS` 字典中添加即可。例如在 `idor_order_scanner.py`:

```python
FRAMEWORK_PRESETS["my-framework"] = {
    "method": "POST",
    "endpoint": "/api/v1/orders",
    "body_template": '{"page": 1}',
    "headers": {"Content-Type": "application/json"},
}
```

## 案例映射

每个工具的来源案例记录在脚本头部注释中。新案例的发现应回填到对应工具的预设/域名列表中。

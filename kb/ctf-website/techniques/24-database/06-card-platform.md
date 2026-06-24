# Digital Goods Delivery Security — 数字商品交付安全

> 数字商品（卡密/CDK/激活码/下载链接）的交付链路涉及库存管理、订单查询、支付回调等多个数据库交互点。本指南分析该类平台的通用数据库安全模式与常见缺陷。

## 关键词

`数字商品` `卡密交付` `库存泄露` `订单枚举` `归属校验` `PHP die缺失` `CDK明文存储` `innerHTML XSS` `支付回调` `CSRF绕过`

## 0. 数字商品交付数据流

```
用户下单 → 支付回调 → 写入订单+扣减库存 → 查询订单 → 展示卡密/下载链接
              │                    │              │              │
         [签名校验]           [INSERT/UPDATE]  [SELECT]     [前端渲染]
```

每个环节都涉及数据库读写，任一环节的校验缺失都可能导致数据泄露。

## 1. 库存全量泄露

### 1.1 PHP 流程控制缺陷

校验函数输出错误信息后未 `die()`/`exit()`，后续 SQL 继续执行。

```php
// 缺陷
function show() {
    if (!validate($input)) {
        echo error_page();     // 无 die()，继续执行
    }
    $data = query_all($input); // WHERE id = 0 → 全表匹配
    render($data);             // 全量输出
}

// 修复
function show() {
    if (!validate($input)) {
        echo error_page();
        return;                // ← 显式终止
    }
    $data = query_all($input);
    render($data);
}
```

### 1.2 空值聚合查询

```sql
-- 缺陷：order_id=0 或 NULL 时匹配全表
SELECT * FROM inventory WHERE order_id = 0;

-- 修复：空值显式拒绝
if (!$order_id) { return error('参数错误'); }
```

## 2. 订单枚举与归属缺失

### 2.1 CSRF 校验不等于认证

```http
# 仅校验请求头，未校验登录态
POST /api/query HTTP/1.1
Referer: https://target/
X-Requested-With: XMLHttpRequest
Cookie: PHPSESSID=<匿名>

type=account&keyword=1&page=1
```

### 2.2 响应中的敏感字段

```json
{
  "isnext": true,
  "data": [{
    "id": "176109",
    "product_id": "72122",
    "product_name": "商品名称",
    "result": "CDK 明文内容",     // ← 应脱敏
    "detail_key": "aa39ed38..."   // ← 可用于读取详情
  }]
}
```

### 2.3 分页遍历

`isnext=true` → 递增 `page` → 遍历全量。同时支持按 ID 前缀搜索缩小范围。

### 2.4 修复

- 列表接口强制登录 + 归属过滤
- `result` 字段脱敏返回
- `detail_key` 与登录态绑定校验

## 3. 详情接口双重校验绕过

```http
POST /api/detail HTTP/1.1
Cookie: PHPSESSID=<匿名>

id=176109&key=aa39ed38...
```

`id + key` 双参数设计本身合理，但 key 可通过列表接口获取，且不校验请求者是否为订单购买人。

```json
// 额外暴露字段
{
  "html_content": "<div>CDK HTML</div>",   // 前端直接 innerHTML
  "description": "商品描述 HTML（含外链）",
  "price": "16.50",
  "buyer_info": "账号：xxx"
}
```

## 4. 前端渲染注入

### 4.1 服务端 HTML 直接拼接

```javascript
// 缺陷：服务端返回的 HTML 片段直接 innerHTML
element.innerHTML += data.html_field;

// 修复
element.textContent = data.text_field;
// 或：DOMPurify.sanitize(data.html_field)
```

### 4.2 存储-读取-渲染链路

```
存储时: WAF 过滤 <script>/onerror → 但自定义元素 <x-custom> 可绕过
读取时: escape() → 存入 DOM 属性
渲染时: unescape() → .html() → XSS 执行
```

### 4.3 WAF 绕过注意

- `data:text/html;base64,...` 格式可绕过标签过滤
- 自定义 HTML 元素（`<x-custom>`）不在 WAF 黑名单中

## 5. 支付回调签名缺失

```http
POST /callback/wxpay HTTP/1.1
Content-Type: application/xml

<xml>
  <out_trade_no>1</out_trade_no>
  <transaction_id>fake</transaction_id>
</xml>
```

签名校验失败时仅返回错误 XML，但如果签名逻辑可绕过（固定 salt、弱 MD5、无时间戳校验），则可重放/篡改回调。

## 6. 统计信息泄露

```
GET /api/stats
→ {"days":838, "orders":0, "revenue":0}
```

无认证返回运营统计数据，可用于侦察阶段评估目标价值。

## 7. 修复清单

| 优先级 | 措施 | 影响 |
|--------|------|------|
| P0 | 校验失败显式终止（die/return） | 数据泄露 |
| P0 | 空值/零值查询前拒绝 | 数据泄露 |
| P0 | 列表/详情接口强制登录+归属 | 越权 |
| P0 | 敏感字段脱敏返回 | 越权 |
| P0 | 前端渲染消毒（DOMPurify） | XSS |
| P1 | 支付回调签名+时间戳+幂等 | 伪造支付 |
| P1 | WAF 补充自定义元素+data: 拦截 | XSS |
| P2 | 统计接口加认证 | 信息泄露 |
| P2 | 全局 CSRF Token | CSRF |

## 8. 关联技术

- [[01-sqli-fundamentals]] — SQL 注入
- [[04-config-exposure]] — 配置泄露
- [[payment-digital-goods]] — 数字商品交付
- [[01-idor-enumeration]] — IDOR 枚举
- [[payment-php]] — PHP 支付攻击

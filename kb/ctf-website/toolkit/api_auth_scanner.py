"""
CTF Toolkit: API Auth Boundary Scanner
=====================================
对已发现的API端点列表逐条测试是否需要认证，自动分类：无需认证 / 需登录 / 需验证码 / 404。

用法:
    # 从文件读取端点列表
    python api_auth_scanner.py --url https://target --endpoints endpoints.txt

    # 使用内置支付CTF预设端点
    python api_auth_scanner.py --url https://target --preset payment

    # 输出到JSON
    python api_auth_scanner.py --url https://target --preset payment -o api_map.json

预设:
    payment  - 支付CTF常见API端点 (订单/支付/余额/回调)
    general  - 通用Web CTF端点 (用户/管理/搜索/导出)
"""
import argparse
import json
import sys
from pathlib import Path

import requests

# ============================================================
# Preset Endpoint Lists (from real case experience)
# ============================================================

PAYMENT_API_PRESETS = [
    # 商品/分类
    ("GET",  "/user/api/index/data",          "分类列表"),
    ("GET",  "/user/api/index/commodity",     "商品列表"),
    ("POST", "/user/api/index/valuation",     "价格计算"),
    ("POST", "/user/api/index/stock",         "库存查询"),
    ("POST", "/user/api/index/pay",           "支付方式列表"),
    ("POST", "/user/api/index/card",          "卡密选号"),
    # 订单
    ("POST", "/user/api/order/trade",         "创建订单"),
    ("POST", "/user/api/index/query",         "订单查询 (IDOR!)"),
    ("GET",  "/user/personal/purchaseRecord", "购买记录"),
    # 用户
    ("POST", "/user/api/authentication/login",         "登录"),
    ("POST", "/user/api/authentication/register",      "注册"),
    ("POST", "/user/api/authentication/emailRegisterCaptcha", "邮箱验证码"),
    # 支付回调
    ("POST", "/pay/return",     "支付返回"),
    ("POST", "/pay/notify",     "支付回调"),
    ("POST", "/notify",         "通用回调"),
    ("POST", "/callback",       "通用回调2"),
    ("POST", "/plugin/epay/notify", "Epay回调"),
    # 管理
    ("GET",  "/admin",          "管理后台"),
    ("GET",  "/admin/login",    "管理登录"),
    # 其他
    ("GET",  "/install",        "安装向导"),
    ("GET",  "/.env",           "环境变量泄露"),
    ("GET",  "/runtime.log",    "运行日志泄露"),
]

GENERAL_API_PRESETS = [
    ("GET",  "/api/user",       "用户信息"),
    ("GET",  "/api/search",     "搜索"),
    ("GET",  "/api/export",     "导出"),
    ("GET",  "/api/config",     "配置"),
    ("GET",  "/swagger.json",   "API文档"),
    ("GET",  "/openapi.json",   "OpenAPI"),
    ("GET",  "/graphql",        "GraphQL"),
    ("GET",  "/.git/HEAD",      "Git泄露"),
    ("GET",  "/robots.txt",     "robots"),
    ("GET",  "/sitemap.xml",    "sitemap"),
]


# ============================================================
# Core Scanner
# ============================================================

class APIAuthScanner:
    """API认证边界扫描器"""

    # 认证拦截关键词
    AUTH_BLOCKERS = [
        "登录", "login", "请先登录", "会话过期", "session expire",
        "请登录", "认证失败", "未登录", "unauthorized", "token",
        "权限不足", "forbidden", "403"
    ]

    CAPTCHA_BLOCKERS = [
        "验证码", "captcha", "人机验证"
    ]

    def __init__(self, base_url: str, session: requests.Session = None):
        self.base = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.results = []

    def scan_endpoint(self, method: str, path: str, label: str = "",
                     body: str = "") -> dict:
        """测试单个端点"""
        url = f"{self.base}{path}"
        result = {"method": method, "path": path, "label": label}

        try:
            if method == "POST":
                r = self.session.post(url, data=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=15, allow_redirects=False)
            else:
                r = self.session.get(url, timeout=15, allow_redirects=False)

            result["status"] = r.status_code
            result["length"] = len(r.content)
            result["content_type"] = r.headers.get("content-type", "")

            text_lower = r.text.lower()
            body_preview = r.text[:300]

            # 分类
            if r.status_code == 404 or "404 not found" in text_lower:
                result["auth_level"] = "not_found"
            elif any(kw in text_lower for kw in self.AUTH_BLOCKERS):
                result["auth_level"] = "auth_required"
            elif any(kw in text_lower for kw in self.CAPTCHA_BLOCKERS):
                result["auth_level"] = "captcha_required"
            elif r.status_code in (200, 302) and len(r.content) > 100:
                result["auth_level"] = "open"
            elif r.status_code == 403:
                result["auth_level"] = "blocked_waf"
            else:
                result["auth_level"] = "unknown"

            result["preview"] = body_preview

        except Exception as e:
            result["status"] = 0
            result["auth_level"] = "error"
            result["error"] = str(e)

        return result

    def scan_all(self, endpoints: list[tuple]) -> list[dict]:
        """批量扫描"""
        for method, path, label in endpoints:
            result = self.scan_endpoint(method, path, label)
            self.results.append(result)
            icon = {"open": "[+]", "auth_required": "[-]",
                    "captcha_required": "[?]", "not_found": "[x]",
                    "blocked_waf": "[W]", "error": "[!]"}.get(result["auth_level"], "[?]")
            print(f"  {icon} {method:4s} {path:45s} {result['auth_level']:15s} "
                  f"({result['status']}, {result['length']}B)")
        return self.results

    def summary(self) -> dict:
        """生成分类汇总"""
        counts = {}
        for r in self.results:
            level = r.get("auth_level", "unknown")
            counts[level] = counts.get(level, 0) + 1

        open_endpoints = [r for r in self.results if r["auth_level"] == "open"]
        auth_endpoints = [r for r in self.results if r["auth_level"] == "auth_required"]
        captcha_endpoints = [r for r in self.results if r["auth_level"] == "captcha_required"]

        return {
            "total": len(self.results),
            "counts": counts,
            "open_count": len(open_endpoints),
            "open_endpoints": [(r["method"], r["path"], r["label"]) for r in open_endpoints],
            "auth_required": [(r["method"], r["path"]) for r in auth_endpoints],
            "captcha_required": [(r["method"], r["path"]) for r in captcha_endpoints],
        }


def main():
    parser = argparse.ArgumentParser(description='API Auth Boundary Scanner')
    parser.add_argument('--url', required=True, help='目标URL')
    parser.add_argument('--preset', choices=['payment', 'general'],
                       help='使用内置端点列表')
    parser.add_argument('--endpoints', help='自定义端点文件 (每行: METHOD /path 描述)')
    parser.add_argument('--output', '-o', help='保存结果到JSON')
    args = parser.parse_args()

    scanner = APIAuthScanner(args.url)

    # Load endpoints
    if args.endpoints:
        endpoints = []
        for line in Path(args.endpoints).read_text().splitlines():
            parts = line.strip().split(maxsplit=2)
            if len(parts) >= 2:
                endpoints.append((parts[0], parts[1], parts[2] if len(parts) > 2 else ""))
    elif args.preset == 'payment':
        endpoints = PAYMENT_API_PRESETS
    elif args.preset == 'general':
        endpoints = GENERAL_API_PRESETS
    else:
        endpoints = PAYMENT_API_PRESETS + GENERAL_API_PRESETS

    print(f"[*] 扫描 {len(endpoints)} 个端点 → {args.url}")
    print("=" * 80)

    scanner.scan_all(endpoints)

    summary = scanner.summary()
    print(f"\n{'='*80}")
    print(f"汇总: {summary['total']} 端点")
    print(f"  无需认证: {summary['open_count']}")
    print(f"  需登录:   {len(summary['auth_required'])}")
    print(f"  需验证码: {len(summary['captcha_required'])}")
    print(f"  分类统计: {summary['counts']}")

    if summary['open_endpoints']:
        print(f"\n[!] 无需认证的端点 (优先攻击面):")
        for method, path, label in summary['open_endpoints']:
            print(f"  {method:4s} {path:45s} {label}")

    if args.output:
        Path(args.output).write_text(json.dumps({
            "results": scanner.results,
            "summary": summary
        }, ensure_ascii=False, indent=2))
        print(f"\n[+] 保存到: {args.output}")


if __name__ == '__main__':
    main()

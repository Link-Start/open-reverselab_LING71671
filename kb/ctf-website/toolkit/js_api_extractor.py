"""
CTF Toolkit: JS API Extractor
=============================
从目标页面全量抓取JS（内联+外链），正则提取API端点、路径、参数名。

用法:
    # 通过 requests 抓取 (无CF保护时)
    python js_api_extractor.py --url https://target/item/1

    # 分析本地JS文件
    python js_api_extractor.py --files ./js_dump/*.js

    # 通过 Playwright 浏览器抓取 (有CF保护时)
    python js_api_extractor.py --url https://target --playwright

    # 输出JSON
    python js_api_extractor.py --url https://target -o api_map.json
"""
import argparse
import json
import re
import sys
from pathlib import Path
from collections import defaultdict

# ============================================================
# Extraction Patterns
# ============================================================

# API 路径模式
API_PATTERNS = [
    # util.post/get/put/delete('url', ...)
    (r"util\.(?:post|get|put|delete)\s*\(\s*['\"](/[^'\"]+)['\"]", "util_call"),
    # url: '/api/...'
    (r"url\s*:\s*['\"](/[^'\"]+)['\"]", "url_key"),
    # fetch('/api/...')
    (r"fetch\s*\(\s*['\"](/[^'\"]+)['\"]", "fetch"),
    # $.ajax / $.post / $.get
    (r"\$\.(?:ajax|post|get)\s*\(\s*['\"](/[^'\"]+)['\"]", "jquery_ajax"),
    # window.location.href = '/...'
    (r"window\.location\.href\s*=\s*['\"](/[^'\"]+)['\"]", "redirect"),
    # href="/..."
    (r"href\s*=\s*['\"](/[^'\"]+)['\"]", "link"),
    # axios/fetch POST with path
    (r"(?:axios\.(?:post|get)|fetch)\s*\(\s*`([^`]+)`", "template_literal"),
    # action="..." in forms
    (r"action\s*=\s*['\"](/[^'\"]+)['\"]", "form_action"),
]

# 参数提取模式
PARAM_PATTERNS = [
    (r"(?:post|data)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]", "bracket_access"),
    (r"\.val\s*\(\s*\)|input\[name\s*=\s*['\"]([^'\"]+)['\"]", "input_name"),
    (r"name\s*:\s*['\"]([a-zA-Z_]\w*)['\"]", "param_name"),
    (r"['\"]([a-zA-Z_]\w*)['\"]\s*:", "json_key"),
]

# Flag
FLAG_PATTERN = r'(?:flag|ctf|dasctf)\{[^}]+\}'


# ============================================================
# Core Extractor
# ============================================================

class JSAPIExtractor:
    """从JS代码中提取API端点"""

    def __init__(self):
        self.endpoints = defaultdict(set)  # {method: {urls}}
        self.params = set()
        self.flags = []
        self.sources = []

    def extract_from_text(self, js_text: str, source: str = "inline"):
        """从JS文本中提取"""
        self.sources.append(source)

        # 提取API路径
        for pattern, category in API_PATTERNS:
            for match in re.finditer(pattern, js_text, re.IGNORECASE):
                url = match.group(1)
                if url and not url.startswith('//') and not url.startswith('http'):
                    self.endpoints[category].add(url)

        # 提取参数名
        for pattern, category in PARAM_PATTERNS:
            for match in re.finditer(pattern, js_text, re.IGNORECASE):
                param = match.group(1)
                if param and len(param) > 1 and not param.startswith('.'):
                    self.params.add(param)

        # 提取flag
        for match in re.finditer(FLAG_PATTERN, js_text, re.IGNORECASE):
            self.flags.append(match.group(0))

    def extract_from_url(self, url: str, session: "requests.Session" = None):
        """从URL抓取JS"""
        import requests
        s = session or requests.Session()
        r = s.get(url, timeout=15, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        })
        r.raise_for_status()
        self.extract_from_text(r.text, source=url)

    def extract_from_page(self, page_url: str, session: "requests.Session" = None):
        """从HTML页面抓取所有JS（内联+外链）"""
        import requests
        s = session or requests.Session()
        r = s.get(page_url, timeout=15, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        })

        html = r.text

        # 提取内联 JS
        for match in re.finditer(r'<script[^>]*>([\s\S]*?)</script>', html):
            inline_js = match.group(1)
            if inline_js.strip() and 'src=' not in match.group(0):
                self.extract_from_text(inline_js, source=f"{page_url} (inline)")

        # 提取外链 JS
        for match in re.finditer(r'script[^>]*src="([^"]+)"', html):
            js_url = match.group(1)
            if js_url.startswith('//'):
                js_url = 'https:' + js_url
            elif js_url.startswith('/'):
                from urllib.parse import urlparse
                parsed = urlparse(page_url)
                js_url = f"{parsed.scheme}://{parsed.netloc}{js_url}"

            try:
                self.extract_from_url(js_url, session=s)
            except Exception as e:
                print(f"  [!] 抓取失败 {js_url}: {e}", file=sys.stderr)

    def extract_from_page_playwright(self, page_url: str, page):
        """通过 Playwright 浏览器上下文抓取（绕过CF）"""
        # 获取页面HTML中所有script标签
        js_code = """
        async () => {
            const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
            const inlineScripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent);
            const results = [];
            for (const src of scripts) {
                try {
                    const r = await fetch(src);
                    results.push({src, text: await r.text()});
                } catch(e) {
                    results.push({src, error: e.message});
                }
            }
            for (let i = 0; i < inlineScripts.length; i++) {
                results.push({src: `inline_${i}`, text: inlineScripts[i]});
            }
            return results;
        }
        """

        js_results = page.evaluate(js_code)
        for item in js_results:
            if 'text' in item:
                self.extract_from_text(item['text'], source=item.get('src', 'unknown'))

    def summary(self) -> dict:
        """生成汇总"""
        all_endpoints = sorted(set().union(*self.endpoints.values()))
        return {
            "total_endpoints": len(all_endpoints),
            "total_unique_params": len(self.params),
            "flags_found": len(self.flags),
            "endpoints_by_category": {k: sorted(v) for k, v in self.endpoints.items()},
            "all_endpoints": all_endpoints,
            "params": sorted(self.params),
            "flags": self.flags,
            "sources": self.sources,
        }


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='JS API Extractor')
    parser.add_argument('--url', help='目标页面URL（自动抓取所有外链和内联JS）')
    parser.add_argument('--files', help='本地JS文件glob（如 ./js/*.js）')
    parser.add_argument('--playwright', action='store_true',
                       help='使用Playwright浏览器抓取（绕过CF）')
    parser.add_argument('--output', '-o', help='保存结果到JSON')
    args = parser.parse_args()

    extractor = JSAPIExtractor()

    if args.playwright and args.url:
        from playwright.sync_api import sync_playwright
        print(f"[*] Playwright → {args.url}")
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page()
            page.goto(args.url, wait_until="networkidle", timeout=30000)
            extractor.extract_from_page_playwright(args.url, page)
            browser.close()

    elif args.url:
        print(f"[*] Requests → {args.url}")
        extractor.extract_from_page(args.url)

    elif args.files:
        from glob import glob
        for f in sorted(glob(args.files)):
            print(f"[*] 分析 {f}")
            extractor.extract_from_text(Path(f).read_text(encoding='utf-8', errors='ignore'),
                                        source=f)

    else:
        parser.print_help()
        return

    summary = extractor.summary()

    print(f"\n{'='*60}")
    print(f"提取完成: {summary['total_endpoints']} 个端点, "
          f"{summary['total_unique_params']} 个参数, "
          f"{summary['flags_found']} 个flag")

    if summary['flags']:
        print(f"\n[🏴] FLAGS:")
        for f in summary['flags']:
            print(f"  {f}")

    print(f"\n[API端点]")
    for ep in summary['all_endpoints']:
        print(f"  {ep}")

    if args.output:
        Path(args.output).write_text(json.dumps(summary, ensure_ascii=False, indent=2))
        print(f"\n[+] 保存到: {args.output}")


if __name__ == '__main__':
    main()

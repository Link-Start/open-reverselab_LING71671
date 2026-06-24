"""
CTF Toolkit: Cloudflare Turnstile Bypass
========================================
使用 Playwright 真实浏览器过 Turnstile challenge，
持久化 cookie 给后续 requests 复用。

用法:
    # 绕过并保存cookie
    python cloudflare_bypass.py --url https://target --save-cookies cf_cookies.json

    # 从保存的cookie恢复
    python cloudflare_bypass.py --url https://target --load-cookies cf_cookies.json --save-cookies cf_new.json

    # 仅验证可访问性
    python cloudflare_bypass.py --url https://target --check-only

依赖: pip install playwright; playwright install chromium
"""
import argparse
import json
import time
from pathlib import Path

# ============================================================
# Core Bypass
# ============================================================

class CloudflareBypass:
    """Playwright-based Cloudflare Turnstile bypass"""

    def __init__(self, headless: bool = False):
        self.headless = headless
        self.browser = None
        self.context = None
        self.page = None

    def start(self):
        """启动浏览器"""
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        self.browser = self._pw.chromium.launch(headless=self.headless)
        self.context = self.browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1920, "height": 1080},
            locale="zh-CN"
        )
        self.page = self.context.new_page()

    def bypass(self, url: str, timeout: int = 30) -> bool:
        """
        导航到目标并等待 Cloudflare challenge 自动完成。
        返回 True 表示成功绕过。
        """
        if not self.page:
            self.start()

        print(f"[*] 导航到 {url}")
        self.page.goto(url, wait_until="domcontentloaded", timeout=timeout)

        # 等待 challenge 完成: 页面标题不再包含 CF 特征
        start = time.time()
        while time.time() - start < timeout:
            title = self.page.title()
            if not any(kw in title.lower() for kw in
                      ["just a moment", "请稍候", "attention required",
                       "ddos", "challenge", "security verification"]):
                body_text = self.page.evaluate("() => document.body?.innerText?.substring(0, 200) || ''")
                if not any(kw in body_text.lower() for kw in
                          ["performing security verification", "正在进行安全验证",
                           "enable javascript and cookies"]):
                    print(f"[+] CF bypassed in {time.time()-start:.1f}s → '{title}'")
                    return True
            time.sleep(1)

        print(f"[!] CF bypass timeout after {timeout}s")
        return False

    def get_cookies(self) -> list[dict]:
        """导出当前浏览器cookies"""
        if not self.context:
            return []
        return self.context.cookies()

    def save_cookies(self, path: str):
        """保存cookies到文件"""
        cookies = self.get_cookies()
        Path(path).write_text(json.dumps(cookies, indent=2))
        print(f"[+] Cookies saved to {path} ({len(cookies)} cookies)")

    def load_cookies(self, path: str):
        """从文件加载cookies到浏览器"""
        if not self.context:
            self.start()
        cookies = json.loads(Path(path).read_text())
        self.context.add_cookies(cookies)
        print(f"[+] Loaded {len(cookies)} cookies from {path}")

    def export_session(self, path: str):
        """
        导出为 Python requests 可用的 session 对象。
        同时在浏览器上下文中保持可用（避免再次触发CF）。
        """
        cookies = self.get_cookies()
        import requests
        s = requests.Session()
        for c in cookies:
            s.cookies.set(c['name'], c['value'], domain=c.get('domain', ''))
        # 同时保存到文件
        Path(path).write_text(json.dumps(cookies, indent=2))
        print(f"[+] Session exported to {path}")
        return s

    def close(self):
        """关闭浏览器"""
        if self.browser:
            self.browser.close()
        if hasattr(self, '_pw'):
            self._pw.stop()


# ============================================================
# Cookie to requests session
# ============================================================

def cookies_to_session(cookie_file: str) -> "requests.Session":
    """从文件加载cookies创建 requests.Session"""
    import requests
    cookies = json.loads(Path(cookie_file).read_text())
    s = requests.Session()
    for c in cookies:
        s.cookies.set(c['name'], c['value'], domain=c.get('domain', ''))
    return s


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='Cloudflare Turnstile Bypass')
    parser.add_argument('--url', required=True, help='目标URL')
    parser.add_argument('--save-cookies', help='保存cookies到文件')
    parser.add_argument('--load-cookies', help='从文件加载cookies')
    parser.add_argument('--check-only', action='store_true', help='仅测试是否可访问')
    parser.add_argument('--headless', action='store_true', help='无头模式')
    parser.add_argument('--timeout', type=int, default=30, help='超时秒数')
    args = parser.parse_args()

    cf = CloudflareBypass(headless=args.headless)
    cf.start()

    if args.load_cookies:
        cf.load_cookies(args.load_cookies)

    success = cf.bypass(args.url, timeout=args.timeout)

    if success:
        if args.save_cookies:
            cf.save_cookies(args.save_cookies)

        if args.check_only:
            print(f"[+] 可访问!")
        else:
            # 显示页面基本信息
            title = cf.page.title()
            body = cf.page.evaluate("() => document.body?.innerText?.substring(0, 500) || ''")
            print(f"[*] Title: {title}")
            print(f"[*] Body preview:\n{body[:300]}")
    else:
        print("[!] CF 绕过失败")

    cf.close()


if __name__ == '__main__':
    main()

"""
CTF Toolkit: CAPTCHA Auto-Solver
===============================
基于 ddddocr 的验证码自动识别，支持三种输入方式。

用法:
    # 1. 从 URL 获取验证码
    python captcha_solver.py --url https://target/user/captcha/image?action=trade

    # 2. 从本地文件
    python captcha_solver.py --file captcha.png

    # 3. 从 base64 字符串
    python captcha_solver.py --base64 "iVBORw0KGgo..."

    # 4. 带 cookie/session（从浏览器复用）
    python captcha_solver.py --url https://target/captcha --cookie "SESSION=xxx"

依赖: pip install ddddocr requests Pillow
"""
import argparse
import base64
import sys
from io import BytesIO
from pathlib import Path

import requests
from PIL import Image

# ============================================================
# Core Solver
# ============================================================

class CaptchaSolver:
    """ddddocr 封装，支持多种输入方式"""

    def __init__(self):
        import ddddocr
        self.ocr = ddddocr.DdddOcr(show_ad=False)

    def solve_bytes(self, data: bytes) -> str:
        """原始字节 → 识别结果"""
        return self.ocr.classification(data)

    def solve_file(self, path: str) -> str:
        """本地文件 → 识别结果"""
        return self.solve_bytes(Path(path).read_bytes())

    def solve_base64(self, b64: str) -> str:
        """base64 → 识别结果"""
        # 去掉 data:image/png;base64, 前缀
        if ',' in b64:
            b64 = b64.split(',')[1]
        return self.solve_bytes(base64.b64decode(b64))

    def solve_url(self, url: str, session: requests.Session = None,
                  cookie_str: str = None) -> tuple[str, bytes]:
        """URL → (识别结果, 图片bytes)。自动处理cookie"""
        s = session or requests.Session()
        if cookie_str:
            s.headers['Cookie'] = cookie_str
        r = s.get(url, timeout=15)
        r.raise_for_status()
        result = self.solve_bytes(r.content)
        return result, r.content


# ============================================================
# Playwright Integration
# ============================================================

def playwright_captcha_pipeline(page, captcha_img_selector: str = '.captcha-img',
                                 captcha_input_selector: str = 'input[name=captcha]',
                                 submit_selector: str = None) -> str:
    """
    完整的 Playwright 验证码自动化管道:
    1. 截图验证码图片
    2. ddddocr 识别
    3. 填入输入框
    4. 可选: 点击提交按钮
    返回识别结果
    """
    img = page.locator(captcha_img_selector).first
    if not img:
        raise ValueError(f"未找到验证码图片: {captcha_img_selector}")

    # 截图转 base64
    import base64 as b64
    screenshot = img.screenshot()
    result = CaptchaSolver().solve_bytes(screenshot)

    # 填入
    page.locator(captcha_input_selector).fill(result)

    # 可选提交
    if submit_selector:
        page.locator(submit_selector).click()

    return result


def playwright_fetch_captcha(page, captcha_url: str) -> str:
    """
    在 Playwright 页面上下文中通过 fetch 获取验证码并识别。
    适合需要 cookie/session 的场景。
    """
    js_code = f"""
    async () => {{
        const r = await fetch('{captcha_url}?t=' + Date.now());
        const blob = await r.blob();
        return new Promise(resolve => {{
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.readAsDataURL(blob);
        }});
    }}
    """
    data_url = page.evaluate(js_code)
    return CaptchaSolver().solve_base64(data_url)


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='ddddocr CAPTCHA Solver')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--url', help='验证码图片URL')
    group.add_argument('--file', help='本地验证码文件路径')
    group.add_argument('--base64', help='base64编码的验证码图片')
    parser.add_argument('--cookie', help='Cookie字符串 (配合--url使用)')
    parser.add_argument('--save', help='保存图片到指定路径')
    parser.add_argument('--retry', type=int, default=1, help='重试次数')
    args = parser.parse_args()

    solver = CaptchaSolver()

    for attempt in range(args.retry):
        try:
            if args.url:
                result, img_bytes = solver.solve_url(args.url, cookie_str=args.cookie)
                if args.save:
                    Path(args.save).write_bytes(img_bytes)
            elif args.file:
                result = solver.solve_file(args.file)
            elif args.base64:
                result = solver.solve_base64(args.base64)

            print(result.strip())
            return

        except Exception as e:
            if attempt < args.retry - 1:
                print(f"[*] 重试 {attempt+1}/{args.retry}: {e}", file=sys.stderr)
                continue
            print(f"[!] 失败: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == '__main__':
    main()

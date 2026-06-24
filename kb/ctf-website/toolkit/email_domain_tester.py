"""
CTF Toolkit: Email Domain Tester
================================
批量测试目标注册API接受哪些邮箱域名，自动分类 ACCEPTED / BLOCKED。

用法:
    python email_domain_tester.py --url https://target --api /user/api/authentication/emailRegisterCaptcha

    # 测试预设域名列表
    python email_domain_tester.py --url https://target --list common

    # 自定义域名列表
    python email_domain_tester.py --url https://target --domains gmail.com,outlook.com,yopmail.com

    # 通过 Playwright browser context 发请求（绕过Cloudflare）
    python email_domain_tester.py --url https://target --playwright

预设列表:
    common    - 主流邮箱 + 常用临时邮箱 (40+)
    temp      - 仅临时邮箱域名 (30+)
    all       - common + temp + 小众域名 (60+)
"""
import argparse
import json
import sys
from pathlib import Path

import requests

# ============================================================
# Domain Lists
# ============================================================

MAINSTREAM_DOMAINS = [
    # 国际主流
    "gmail.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "rocketmail.com",
    "icloud.com", "me.com", "mac.com",
    "proton.me", "protonmail.com", "pm.me",
    # 国内主流
    "qq.com", "foxmail.com",
    "163.com", "126.com", "yeah.net",
    "sina.com", "sina.cn",
    "sohu.com",
    "aliyun.com",
]

TEMP_EMAIL_DOMAINS = [
    # 国际
    "guerrillamail.com", "sharklasers.com", "grr.la",
    "yopmail.com", "yopmail.fr",
    "mailinator.com",
    "maildrop.cc",
    "temp-mail.org", "tempmail.org",
    "10minutemail.com", "10minutemail.net",
    "trashmail.com",
    "mailnesia.com",
    "dispostable.com",
    "moakt.com",
    "emailondeck.com",
    "inboxkitten.com",
    "mailcatch.com",
    "harakirimail.com",
    "tempmail.io",
    # 国内
    "chacuo.net",
    "linshi-email.com", "linshiyou.com",
    "24mail.com",
    # mail.tm
    "mail.tm", "web-library.net", "cloudemail.info", "digital-mail.info",
    # SmailPro
    "devmant.com", "storegmail.net", "smser.net",
    "sydney.edu.pl", "melbourne.edu.pl",
    # 其他
    "cock.li", "tuta.io", "keemail.me",
    "developermail.com", "tempmail.com",
    "mohmal.com", "luxusmail.com", "trash-mail.com",
    "maildim.com", "tmail.com", "nowmymail.com",
    "txcologne.com", "vmail.dev", "email.com",
    "mail.gw", "mail-temp.com", "emailfake.com",
    "smailpro.com", "emailnator.com", "crankymonkey.info",
    "roboreceipt.com",
]


# ============================================================
# Core Tester
# ============================================================

class EmailDomainTester:
    """测试目标注册API的邮箱域名白名单"""

    def __init__(self, base_url: str, api_path: str,
                 method: str = "POST", body_template: str = "captcha=test&email=test@{domain}"):
        self.base = base_url.rstrip('/')
        self.api = api_path
        self.method = method.upper()
        self.body_template = body_template
        self.session = requests.Session()

    def test_domain(self, domain: str) -> dict:
        """测试单个域名。返回 {domain, accepted, msg}"""
        body = self.body_template.replace("{domain}", domain)
        url = f"{self.base}{self.api}"

        try:
            if self.method == "POST":
                r = self.session.post(url, data=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=15)
            else:
                r = self.session.get(url + f"?email=test@{domain}", timeout=15)

            msg = ""
            try:
                msg = r.json().get("msg", "")
            except:
                msg = r.text[:200]

            # 判断逻辑: 验证码错误 = 域名被接受, 不支持 = 域名被拒绝
            accepted = any(kw in msg for kw in
                ["验证码错误", "verification code", "invalid captcha",
                 "captcha", "验证码不正确", "人机验证失败"])

            return {
                "domain": domain,
                "accepted": accepted,
                "status": r.status_code,
                "msg": msg[:100]
            }

        except Exception as e:
            return {"domain": domain, "accepted": False, "error": str(e)}

    def test_all(self, domains: list[str]) -> dict:
        """批量测试"""
        accepted = []
        blocked = []
        errors = []

        for domain in domains:
            result = self.test_domain(domain)
            if result.get("error"):
                errors.append(result)
            elif result["accepted"]:
                accepted.append(result)
            else:
                blocked.append(result)
            print(f"  {domain:30s} {'✓ ACCEPTED' if result['accepted'] else '✗ BLOCKED'} "
                  f"| {result.get('msg', result.get('error', ''))[:60]}")

        return {
            "total": len(domains),
            "accepted_count": len(accepted),
            "blocked_count": len(blocked),
            "error_count": len(errors),
            "accepted": accepted,
            "blocked": blocked,
            "errors": errors,
            # 方便的速查列表
            "accepted_domains": [d["domain"] for d in accepted],
            "blocked_domains": [d["domain"] for d in blocked],
        }


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='Email Domain Whitelist Tester')
    parser.add_argument('--url', required=True, help='目标URL')
    parser.add_argument('--api', default='/user/api/authentication/emailRegisterCaptcha',
                       help='邮箱验证码API路径')
    parser.add_argument('--list', choices=['mainstream', 'temp', 'all'],
                       default='all', help='域名列表')
    parser.add_argument('--domains', help='自定义域名，逗号分隔 (覆盖--list)')
    parser.add_argument('--output', '-o', help='保存结果到JSON')
    args = parser.parse_args()

    # Select domains
    if args.domains:
        domains = [d.strip() for d in args.domains.split(',')]
    elif args.list == 'mainstream':
        domains = MAINSTREAM_DOMAINS
    elif args.list == 'temp':
        domains = TEMP_EMAIL_DOMAINS
    else:
        domains = MAINSTREAM_DOMAINS + TEMP_EMAIL_DOMAINS

    print(f"[*] 测试 {len(domains)} 个域名 → {args.url}{args.api}")
    print("=" * 70)

    tester = EmailDomainTester(args.url, args.api)
    results = tester.test_all(domains)

    print("\n" + "=" * 70)
    print(f"[+] 接受: {results['accepted_count']} | 拒绝: {results['blocked_count']} | 错误: {results['error_count']}")
    if results['accepted']:
        print(f"[+] 可用域名: {', '.join(results['accepted_domains'])}")
    if results['blocked']:
        print(f"[-] 被拒域名: {', '.join(results['blocked_domains'][:10])}...")

    if args.output:
        Path(args.output).write_text(json.dumps(results, ensure_ascii=False, indent=2))
        print(f"\n[+] 保存到: {args.output}")


if __name__ == '__main__':
    main()

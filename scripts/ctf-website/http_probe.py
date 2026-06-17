#!/usr/bin/env python3
"""
HTTP Probe — 快速 HTTP 指纹探测。

Usage:
    python scripts/ctf-website/http_probe.py <url>
    python scripts/ctf-website/http_probe.py http://target.com --headers --body --cookies

Collects: response headers, server banner, cookies, HTML meta, JS libraries, error pages.
"""

import sys


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    url = sys.argv[1]
    print(f"Probing: {url}")
    print("[!] HTTP probe backend not yet configured (requires requests/httpx).")


if __name__ == "__main__":
    main()

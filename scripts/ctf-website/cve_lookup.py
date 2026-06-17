#!/usr/bin/env python3
"""
CVE Lookup — 根据产品/版本查询相关 CVE。

Usage:
    python scripts/ctf-website/cve_lookup.py <product> [version]

Example:
    python scripts/ctf-website/cve_lookup.py "GeoServer" "2.22.0"
"""

import sys


def main():
    product = sys.argv[1] if len(sys.argv) > 1 else None
    version = sys.argv[2] if len(sys.argv) > 2 else None

    if not product:
        print(__doc__)
        return

    print(f"Looking up CVE for: {product} {version or ''}")
    # TODO: Integrate with NVD API / local CVE database
    print("[!] CVE lookup backend not yet configured.")
    print("[!] See: kb/ctf-website/techniques/09-cve/cve-workflow.md")


if __name__ == "__main__":
    main()

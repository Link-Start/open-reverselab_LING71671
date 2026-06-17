#!/usr/bin/env python3
"""
CVE Chain Planner — 基于指纹 + CVE 数据规划多 CVE 利用链。

Usage:
    python scripts/ctf-website/cve_chain_planner.py <fingerprints.json>
    python scripts/ctf-website/cve_chain_planner.py exports/ctf-website/<target>/fingerprints.json
"""

import sys
import json
import os


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    fp_path = sys.argv[1]
    if not os.path.exists(fp_path):
        print(f"[!] Fingerprint file not found: {fp_path}")
        return

    with open(fp_path, "r", encoding="utf-8") as f:
        fingerprints = json.load(f)

    print(f"Loaded {len(fingerprints.get('fingerprints', []))} fingerprints from {fp_path}")
    # TODO: Plan CVE chains from fingerprints
    print("[!] CVE chain planner backend not yet configured.")
    print("[!] See: kb/ctf-website/techniques/09-cve/multi-cve-chain-playbook.md")


if __name__ == "__main__":
    main()

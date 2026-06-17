#!/usr/bin/env python3
"""
CVE Graph — 生成 CVE 关联图谱。

Usage:
    python scripts/ctf-website/cve_graph.py <cve_ids...>
    python scripts/ctf-website/cve_graph.py CVE-2024-1234 CVE-2024-5678

Output: JSON graph of CVE correlations (chainable exploits, shared prerequisites).
"""

import sys
import json


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cve_ids = sys.argv[1:]
    print(f"Building CVE graph for: {', '.join(cve_ids)}")

    # TODO: Build correlation graph from NVD / local data
    graph = {
        "nodes": [{"cve": c, "cvss": None, "epss": None} for c in cve_ids],
        "edges": [],
    }
    print(json.dumps(graph, indent=2))
    print("\n[!] CVE correlation backend not yet configured.")
    print("[!] See: kb/ctf-website/techniques/09-cve/cve-correlation-graph.md")


if __name__ == "__main__":
    main()

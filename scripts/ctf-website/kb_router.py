#!/usr/bin/env python3
"""
Knowledge Base Router — 按信号搜索相关技术文件。

Usage:
    python scripts/ctf-website/kb_router.py "sql injection"
    python scripts/ctf-website/kb_router.py "jwt"
"""

import sys
import json
import os

KB_INDEX = os.path.join(os.path.dirname(__file__), "..", "..", "kb", "ctf-website", "techniques", "kb-index.json")
TECHNIQUES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "kb", "ctf-website", "techniques")


def load_index():
    """Load kb-index.json and return entries."""
    if not os.path.exists(KB_INDEX):
        print(f"[!] kb-index.json not found at {KB_INDEX}")
        print("[!] Run 'python scripts/ctf-website/kb_router.py --build' to create it.")
        return []
    with open(KB_INDEX, "r", encoding="utf-8") as f:
        return json.load(f)


def search(query, index):
    """Simple keyword search over kb-index entries."""
    query_lower = query.lower()
    results = []
    for entry in index:
        score = 0
        for keyword in entry.get("keywords", []):
            if keyword.lower() in query_lower:
                score += 10
        if query_lower in entry.get("title", "").lower():
            score += 5
        if query_lower in entry.get("description", "").lower():
            score += 3
        if score > 0:
            results.append((score, entry))
    results.sort(key=lambda x: x[0], reverse=True)
    return [r[1] for r in results]


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    query = sys.argv[1]
    index = load_index()
    if not index:
        return

    results = search(query, index)
    if not results:
        print(f"No matches for: {query}")
        print("Try broader keywords, or check kb/ctf-website/techniques/attack-network.md")
        return

    print(f"\nResults for '{query}' ({len(results)} found):\n")
    for i, entry in enumerate(results[:10], 1):
        path = os.path.join(TECHNIQUES_DIR, entry.get("file", ""))
        print(f"  {i}. [{entry.get('category', '')}] {entry.get('title', '')}")
        print(f"     {path}")
        print(f"     {entry.get('description', '')[:100]}")
        print()


if __name__ == "__main__":
    main()

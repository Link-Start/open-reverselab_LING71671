#!/usr/bin/env python3
"""
AI Context Generator — 为指定任务自动召回相关工具和历史 findings。

Usage:
    python scripts/misc/ai_context.py "<task>" --save
    python scripts/misc/ai_context.py "web ctf jwt bypass"

Generates a context summary including:
    - Relevant board
    - Recommended tools (from ai-tool-registry.json)
    - Matching finding entries (from kb/ai-findings/)
    - Related KB techniques (from kb_router.py)
"""

import sys
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    task = sys.argv[1]
    save = "--save" in sys.argv

    print(f"Generating AI context for: {task}")
    print()
    print("[!] Context generator backend not yet configured.")
    print("[!] Once set up, this will query tool registry, findings DB, and KB router.")
    print()
    print("Manual steps:")
    print(f"  1. Identify board: Web/Android/Windows/Misc")
    print(f"  2. Read boards/<board>/AI-USAGE.md")
    print(f"  3. Run: python scripts/ctf-website/kb_router.py \"{task}\"")
    print(f"  4. Check: kb/ai-findings/findings.jsonl")


if __name__ == "__main__":
    main()

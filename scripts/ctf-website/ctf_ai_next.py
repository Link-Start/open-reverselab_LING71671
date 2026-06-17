#!/usr/bin/env python3
"""
CTF AI Next — 基于当前状态给出 AI 下一步行动建议。

Usage:
    python scripts/ctf-website/ctf_ai_next.py <case_dir>
    python scripts/ctf-website/ctf_ai_next.py cases/ctf-website/<challenge>/

Analyzes current findings, open questions, and attack network to suggest next steps.
"""

import sys


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    case_dir = sys.argv[1]
    print(f"Analyzing case: {case_dir}")
    # TODO: Read case state, check attack network, suggest next probes
    print("[!] AI next-step engine not yet implemented.")


if __name__ == "__main__":
    main()

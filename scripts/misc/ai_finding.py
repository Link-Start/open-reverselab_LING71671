#!/usr/bin/env python3
"""
AI Finding Manager — 记录和搜索可复用发现。

Usage:
    python scripts/misc/ai_finding.py add --board <board> --kind <kind> --title "..." --trigger "..." --finding "..." --evidence "..." --reuse "..." --keyword ...
    python scripts/misc/ai_finding.py search <keyword>...

Kinds: tactic, pitfall, tool-rule, dead-end, cve-chain, reversing-flow

Records findings to kb/ai-findings/findings.jsonl for later retrieval.
"""

import sys
import json
import os
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FINDINGS_FILE = os.path.join(ROOT, "kb", "ai-findings", "findings.jsonl")

VALID_KINDS = ["tactic", "pitfall", "tool-rule", "dead-end", "cve-chain", "reversing-flow"]


def parse_add_args(args):
    """Parse --key value pairs from add command."""
    record = {}
    i = 0
    while i < len(args):
        if args[i].startswith("--") and i + 1 < len(args):
            key = args[i][2:]
            val = args[i + 1]
            if key == "keyword":
                record.setdefault("keywords", []).append(val)
            else:
                record[key] = val
            i += 2
        else:
            i += 1
    return record


def cmd_add(args):
    record = parse_add_args(args)
    record["timestamp"] = datetime.now().isoformat()
    record["kind"] = record.get("kind", "tactic")

    if record["kind"] not in VALID_KINDS:
        print(f"[!] Invalid kind: {record['kind']}. Valid: {', '.join(VALID_KINDS)}")
        return

    os.makedirs(os.path.dirname(FINDINGS_FILE), exist_ok=True)
    with open(FINDINGS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"Finding added: {record.get('title', 'untitled')}")


def cmd_search(keywords):
    if not os.path.exists(FINDINGS_FILE):
        print("No findings recorded yet.")
        return

    with open(FINDINGS_FILE, "r", encoding="utf-8") as f:
        findings = [json.loads(line) for line in f if line.strip()]

    query = " ".join(keywords).lower()
    results = []
    for f_item in findings:
        score = 0
        for kw in f_item.get("keywords", []):
            if kw.lower() in query:
                score += 10
        if query in f_item.get("title", "").lower():
            score += 5
        if query in f_item.get("finding", "").lower():
            score += 3
        if score > 0:
            results.append((score, f_item))

    results.sort(key=lambda x: x[0], reverse=True)
    print(f"\nMatches for '{' '.join(keywords)}' ({len(results)}):\n")
    for i, (score, f_item) in enumerate(results[:20], 1):
        print(f"  {i}. [{f_item.get('kind')}] {f_item.get('title')}")
        print(f"     {f_item.get('finding', '')[:120]}")
        print()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1]
    if cmd == "add":
        cmd_add(sys.argv[2:])
    elif cmd == "search":
        cmd_search(sys.argv[2:])
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)


if __name__ == "__main__":
    main()

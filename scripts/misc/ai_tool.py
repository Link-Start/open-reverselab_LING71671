#!/usr/bin/env python3
"""
AI Tool Router — 工具调用注册和路由。

Usage:
    python scripts/misc/ai_tool.py plan "<task>"              # 推荐工具
    python scripts/misc/ai_tool.py list --board <board>       # 列出板块工具
    python scripts/misc/ai_tool.py list --callable             # 列出可调用工具
    python scripts/misc/ai_tool.py run <tool_id> -- <args>    # 调用工具

Tool registry: tools/ai-tool-registry.json
Tool playbook:  tools/ai-tool-playbook.json
"""

import sys
import json
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
REGISTRY = os.path.join(ROOT, "tools", "ai-tool-registry.json")
PLAYBOOK = os.path.join(ROOT, "tools", "ai-tool-playbook.json")


def load_json(path, default=None):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default or {}


def cmd_plan(task):
    """Suggest tools for a given task description."""
    playbook = load_json(PLAYBOOK, {})
    registry = load_json(REGISTRY, {})

    print(f"Task: {task}")
    print("[!] Tool registry and playbook not yet populated.")
    print("[!] Create tools/ai-tool-registry.json and tools/ai-tool-playbook.json to enable.")


def cmd_list(board=None, callable_only=False):
    """List tools, optionally filtered by board."""
    registry = load_json(REGISTRY, {})
    if not registry:
        print("[!] Tool registry is empty. Add tools to tools/ai-tool-registry.json")
        return

    for tool_id, tool in registry.items():
        if board and tool.get("board") != board:
            continue
        if callable_only and not tool.get("callable"):
            continue
        print(f"  {tool_id}: {tool.get('description', '')}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1]

    if cmd == "plan":
        task = sys.argv[2] if len(sys.argv) > 2 else ""
        cmd_plan(task)
    elif cmd == "list":
        board = None
        callable_only = False
        args = sys.argv[2:]
        for i, a in enumerate(args):
            if a == "--board" and i + 1 < len(args):
                board = args[i + 1]
            if a == "--callable":
                callable_only = True
        cmd_list(board=board, callable_only=callable_only)
    elif cmd == "run":
        tool_id = sys.argv[2] if len(sys.argv) > 2 else ""
        print(f"Run: {tool_id}")
        print("[!] Tool runner not yet implemented.")
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)


if __name__ == "__main__":
    main()

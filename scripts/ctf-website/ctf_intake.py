#!/usr/bin/env python3
"""
CTF Intake — 新建 CTF 题目，初始化目录结构和 case 索引。

Usage:
    python scripts/ctf-website/ctf_intake.py <challenge_name> --url <url> --board ctf-website
"""

import sys


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    name = sys.argv[1]
    print(f"Intaking new CTF challenge: {name}")
    # TODO: Create case directory, copy templates, initialize links
    print("[!] CTF intake stub — full automation not yet implemented.")


if __name__ == "__main__":
    main()

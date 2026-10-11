#!/usr/bin/env python3
"""Prevent literal backslash-n followed by a new Bash command in .sh files."""
import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parent.parent
suspicious = re.compile(
    r'\\n[ \t]+(?:echo|ip|tc|sysctl|iptables|nft|if|for|while|local|export|'
    r'printf|sudo|systemctl|return|exit|mkdir|mv|cp|rm|cat)\b')
failures = []
checked = 0
for path in root.rglob("*.sh"):
    if ".git" in path.parts:
        continue
    checked += 1
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if suspicious.search(line):
            failures.append((str(path.relative_to(root)), index, line[:150]))
if failures:
    for file, line, content in failures:
        print(f"FAIL {file}:{line}: escaped literal newline before command: {content}")
    sys.exit(1)
print(f"PASS: no malformed Bash command separators among {checked} shell files")

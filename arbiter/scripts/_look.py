#!/usr/bin/env python3
"""Scratch: print the composed file around a named error, for hand-checking blame."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
run, want = sys.argv[1], sys.argv[2]
lo, hi = (int(x) for x in sys.argv[3].split("-")) if len(sys.argv) > 3 else (1, 400)

rows = [json.loads(l) for l in
        (ROOT / "runs" / f"{run}.results.jsonl").read_text(encoding="utf-8").splitlines()
        if l.strip()]
for row in rows:
    for poc in (row.get("outcome") or {}).get("pocs", []):
        if poc.get("name") != want or poc.get("compiled"):
            continue
        lines = (poc.get("solidity") or "").splitlines()
        print(f"### {want}  ({len(lines)} lines)  adjudicated={poc.get('adjudicated')}")
        for i, ln in enumerate(lines, 1):
            if lo <= i <= hi:
                print(f"{i:>4}| {ln}")
        print("--- compiler ---")
        print(poc.get("output_tail") or "")
        raise SystemExit(0)
print("not found")

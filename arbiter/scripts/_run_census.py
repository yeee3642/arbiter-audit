#!/usr/bin/env python3
"""Error census for a run, plus the specific ways today's repairs could have backfired."""
from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

# Things that would mean the repair itself is the problem.
SUSPECT = {
    "assert overload ambiguity": r"No unique declaration found",
    "storage refusal fired": r"declares a storage pointer",
    "renamed symbol unresolved": r"_arb",
    "tuple rewrite artefact": r"Different number of components",
    "composition refusal": r"harness would have to lift|must declare the contract under audit",
}

for run in sys.argv[1:] or ["refixed1"]:
    rows = [json.loads(l) for l in
            Path(f"runs/{run}.results.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    blob_all = json.dumps(rows, ensure_ascii=False)

    errs = collections.Counter(re.findall(r"Error \(\d+\): [^\"\\\n]{0,58}", blob_all))
    stop = collections.Counter((r.get("outcome") or {}).get("stop_reason") for r in rows)

    print(f"=== {run}: {len(rows)} samples ===")
    print("  stop_reason:", dict(stop))
    print("  top compiler errors:")
    for k, v in errs.most_common(12):
        print(f"    {v:4d}  {k.strip()}")
    print("  suspects (would mean the repair backfired):")
    for name, pat in SUSPECT.items():
        n = len(re.findall(pat, blob_all))
        flag = "  <<<" if n else ""
        print(f"    {n:4d}  {name}{flag}")

    fn = [r for r in rows if r["truth"] == "vuln" and r.get("predicted") != "vuln"]
    print(f"  false negatives: {len(fn)}")
    fnstop = collections.Counter((r.get("outcome") or {}).get("stop_reason") for r in fn)
    print("    stop_reason:", dict(fnstop))
    print()

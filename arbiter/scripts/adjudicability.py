#!/usr/bin/env python3
"""Two things about the baseline that the confusion matrix cannot show.

**Can its findings be adjudicated at all.** The comparison everyone reaches for is
"whose F1 is higher", and it is the wrong one. A finding here is a transcript of an
execution; a finding there is a paragraph. Nothing in the baseline's output can be run,
so no third party -- ours or anyone's -- can check a single one of its claims by
executing it. That is not a criticism of its accuracy. It is a statement about what
kind of object it produces.

**Why its MCC is 0.000.** The aggregate number says the arm carries no information, but
not where that comes from. The baseline is an ensemble of independent detectors over a
PAIRED benchmark, so each detector can be scored on its own: a detector that fires on
the vulnerable half of a pair and not on the patched half has told you something, and
one that fires on both has told you nothing. The aggregate is degenerate because almost
every part of it is.

Costs no gateway requests -- it reads a recorded run.

    python3 scripts/adjudicability.py --jobs runs/h2h-bastet.jobs.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

# Anything a harness could take and run: Solidity, a test, a transaction, a call.
EXECUTABLE = re.compile(
    r"contract\s+\w+\s*\{|function\s+test\w*\s*\(|pragma\s+solidity|"
    r"forge\s+test|cast\s+send|0x[0-9a-fA-F]{40}\.call",
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=Path, required=True,
                    help="the baseline's jobs.jsonl")
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args()

    rows = [
        json.loads(line)
        for line in args.jobs.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    # ---- adjudicability -------------------------------------------------------------
    findings = 0
    executable = 0
    for row in rows:
        n = row.get("n_findings") or 0
        findings += n
        if n and EXECUTABLE.search(row.get("raw_head") or ""):
            executable += n

    # ---- per-detector discrimination on the paired benchmark ------------------------
    # A pair is (V_x, S_x). Only the pairs where BOTH halves were run count, because a
    # detector cannot be scored on a pair it only saw one side of.
    fired: dict[str, set[str]] = defaultdict(set)
    seen: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        sample, det = row.get("sample", ""), row.get("detector", "")
        if not sample.startswith(("V_", "S_")):
            continue
        seen[det].add(sample)
        if row.get("n_findings"):
            fired[det].add(sample)

    stats: list[dict[str, Any]] = []
    for det, samples in seen.items():
        pairs = {s[2:] for s in samples if s.startswith("V_")} & {
            s[2:] for s in samples if s.startswith("S_")
        }
        if not pairs:
            continue
        on_vuln = sum(1 for p in pairs if f"V_{p}" in fired[det])
        on_safe = sum(1 for p in pairs if f"S_{p}" in fired[det])
        both = sum(1 for p in pairs
                   if f"V_{p}" in fired[det] and f"S_{p}" in fired[det])
        stats.append({
            "detector": det, "pairs": len(pairs),
            "fired_on_vuln": on_vuln, "fired_on_safe": on_safe,
            "fired_on_both": both,
            # The only thing that counts: fired on the defect and NOT on its fix.
            "discriminated": on_vuln - both,
        })

    stats.sort(key=lambda s: (-s["discriminated"], -s["fired_on_vuln"], s["detector"]))
    silent = [s for s in stats if s["fired_on_vuln"] == 0 and s["fired_on_safe"] == 0]
    live = [s for s in stats if s not in silent]

    print(f"{'detector':<46} {'pairs':>6} {'V':>4} {'S':>4} {'both':>5} {'discr':>6}")
    print("-" * 76)
    for s in live:
        print(f"{s['detector'][:46]:<46} {s['pairs']:>6} {s['fired_on_vuln']:>4} "
              f"{s['fired_on_safe']:>4} {s['fired_on_both']:>5} {s['discriminated']:>6}")
    print("-" * 76)
    print(f"{len(silent)} detector(s) never fired at all and are omitted.")

    any_discr = [s for s in stats if s["discriminated"] > 0]
    print()
    print(f"  findings produced:            {findings}")
    print(f"  carrying anything executable: {executable}"
          f"  ({executable / findings if findings else 0:.1%})")
    print(f"  detectors scored on pairs:    {len(stats)}")
    print(f"  ...that ever discriminated:   {len(any_discr)}")
    if any_discr:
        for s in any_discr[:8]:
            print(f"      {s['detector'][:52]:<54} {s['discriminated']}")
    print()
    print("  A finding nobody can execute cannot be adjudicated by anyone -- the point")
    print("  is not that our judge rejects them, it is that there is nothing to run.")

    if args.json:
        args.json.write_text(
            json.dumps({"findings": findings, "executable": executable,
                        "detectors": stats}, indent=1), encoding="utf-8")
        print(f"\n  detail: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

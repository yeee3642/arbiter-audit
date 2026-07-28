#!/usr/bin/env python3
"""Read /tmp/proof_audit.jsonl and say plainly which claimed proofs survive."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PATH = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/proof_audit.jsonl")


def failures(rec: dict) -> list[str]:
    bad: list[str] = []
    if rec.get("patched_sample"):
        bad.append("PATCHED-SAMPLE")
    if rec.get("halts"):
        bad.append("HALTS-BEFORE-PREDICATE")
    if rec.get("negation") == "STILL PASSES":
        bad.append("PASSES-WITHOUT-ATTACK")
    if rec.get("reproduces") is False:
        bad.append("NO-LONGER-REPRODUCES")
    if rec.get("error"):
        bad.append("ERR:" + str(rec["error"])[:44])
    return bad


def main() -> int:
    records = [
        json.loads(line)
        for line in PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    total = len(records)

    def count(pred) -> int:
        return sum(1 for r in records if pred(r))

    print(f"total called proven          {total}")
    print(f"  reproduce on re-run        {count(lambda r: r.get('reproduces'))}")
    print(f"  did NOT reproduce          {count(lambda r: r.get('reproduces') is False)}")
    print(f"  on a PATCHED sample        {count(lambda r: r.get('patched_sample'))}")
    print(f"  halt before the predicate  {count(lambda r: r.get('halts'))}")
    print(f"  PASS WITH ATTACK REMOVED   "
          f"{count(lambda r: r.get('negation') == 'STILL PASSES')}")

    survivors = [r for r in records if not failures(r)]
    rate = len(survivors) / total if total else 0.0
    print(f"\nsurvive every check          {len(survivors)}  ({rate:.0%})")

    print("\n--- claimed proofs that FAILED the audit ---")
    for rec in sorted(records, key=lambda r: (r.get("run", ""), r.get("sample_id", ""))):
        bad = failures(rec)
        if bad:
            print(f"  {str(rec.get('run'))[:16]:<18} {str(rec.get('sample_id'))[:44]:<46} "
                  f"{','.join(bad)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

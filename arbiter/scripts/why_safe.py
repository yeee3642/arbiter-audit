#!/usr/bin/env python3
"""Why one audit concluded safe: what was attempted, and what stopped it.

A `safe` verdict is the one this project is least able to defend, because it is what a
broken toolchain, a composition the gates refused, and a genuinely sound contract all
look like from outside. This prints the difference.

    python3 scripts/why_safe.py runs/<id>.results.jsonl [sample_id]
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ERR = re.compile(r"^(Error \(\d+\): .*|.*revert.*)$")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    rows = [
        json.loads(line)
        for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(sys.argv) > 2:
        rows = [r for r in rows if sys.argv[2] in r["sample_id"]]

    for row in rows:
        out = row.get("outcome") or {}
        pocs = out.get("pocs") or []
        print(f"{row['sample_id']}  truth={row.get('truth', '?')} "
              f"predicted={row.get('predicted')}  stop={out.get('stop_reason')}  "
              f"turns={out.get('turns')}")
        ctx = row.get("context") or {}
        print(f"  context ok={ctx.get('ok')} mode={ctx.get('mode')} "
              f"solc={ctx.get('solc', '-')}")
        if not pocs:
            print("  NO EXPLOIT WAS EVER COMPOSED -- the agent never reached run_exploit,"
                  " or every call was refused before composition.")
        for p in pocs:
            tail = p.get("output_tail") or ""
            errs = [l.strip() for l in tail.splitlines()
                    if l.strip().startswith("Error (")]
            reverts = [l.strip() for l in tail.splitlines()
                       if "ARBITER:" in l or "Arbiter" in l]
            name = str(p.get("name") or "?")[:30]
            print(f"  {name:32s} compiled={p.get('compiled')} "
                  f"passed={p.get('passed')} adjudicated={p.get('adjudicated')} "
                  f"predicate={p.get('predicate')}")
            for e in errs[:2]:
                print(f"      compile: {e[:150]}")
            for r in reverts[:2]:
                print(f"      verdict: {r[:150]}")
        for note in (out.get("rejected_submissions") or [])[:3]:
            print(f"  refused submission: {str(note)[:150]}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

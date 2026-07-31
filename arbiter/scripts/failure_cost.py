#!/usr/bin/env python3
"""What a FAILED attempt costs the agent, in characters returned.

Compile failure is a cheap failure and "compiled, ran, extracted nothing" is an expensive
one, and the three runs that measured that are the reason this script exists. Removing
compile errors between `h2h-arbiter` and `refixed1` moved 33 of 40 samples onto the
turn ceiling and pushed context per request from 15,037 to 21,441 tokens; recall went
0.450 -> 0.100 and only came back when max_turns went 16 -> 26. The budget is turns, so
the thing to optimise is cost per failed attempt, not the number of failures.

Every returned character is paid for twice: once in the response, and then again in every
later request of the same conversation, because it stays in the transcript. So this counts
characters returned per failed attempt, over the failures actually recorded in
`runs/*.results.jsonl`, and compares the renderer as it was against the renderer as it is.

Exact for the part the harness composes -- the numbered listing is a pure function of the
recorded `solidity`, so both the old and the new size are reproducible from the record.
The forge portion is only a lower bound: `PocRecord.as_dict` keeps the last 1200
characters and the live cap is 6000, so where this says "forge >=" the true figure is
larger and the saving below is understated.

No gateway requests, no forge.
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from arbiter.tools import (  # noqa: E402
    _NOHARM_LEGEND, _SOLC_LOC_RE, _composed_view, _numbered_listing,
)


def failures(run: str):
    """Yield (audit_key, poc) for every adjudicated attempt that did not pass.

    One row is one dispatcher -- `run.py` reassigns `outcome` per attempt and records the
    last -- so `(sample_id, repeat)` is the unit a once-per-audit legend is counted over.
    Free-form PoCs are skipped: the harness copies the agent's file out whole and composes
    nothing, so there is no rendering of ours to charge for.
    """
    path = ROOT / "runs" / f"{run}.results.jsonl"
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    for row in rows:
        key = (row.get("sample_id"), row.get("repeat"))
        for poc in (row.get("outcome") or {}).get("pocs", []):
            if poc.get("adjudicated") and not poc.get("passed"):
                yield key, poc


def main() -> int:
    for run in sys.argv[1:] or ["refixed2"]:
        build_before, build_after = [], []
        missed = 0
        audits_with_run_failure: set = set()
        ran = 0
        for key, poc in failures(run):
            sol = poc.get("solidity") or ""
            out = poc.get("output_tail") or ""
            if poc.get("compiled"):
                ran += 1
                audits_with_run_failure.add(key)
                continue
            name = str(poc.get("name") or "")
            listing = _numbered_listing(sol.splitlines())
            build_before.append(len(listing[:7000]))
            build_after.append(len(_composed_view(sol, out, name)))
            # The old listing was cut at 7000 characters, which is roughly the first 150
            # lines. Anything solc named past that was simply not in what came back.
            shown = listing[:7000].count("\n") + 1
            if any(int(m.group(2)) > shown for m in _SOLC_LOC_RE.finditer(out)
                   if m.group(1).endswith(f"{name}.t.sol")):
                missed += 1

        print(f"=== {run} ===")
        print(f"  {len(build_before)} compile failures, {ran} ran-and-failed, "
              f"all harness-composed")
        if build_before:
            b, a = sum(build_before), sum(build_after)
            print("  the composed file, echoed back on a compile failure:")
            print(f"    before  median {statistics.median(build_before):8.0f} chars   "
                  f"total {b:,}")
            print(f"    after   median {statistics.median(build_after):8.0f} chars   "
                  f"total {a:,}")
            print(f"    saved   {b - a:,} chars over the run "
                  f"({100 * (b - a) / b:.0f}% of the listing)")
            print(f"    and in {missed} of {len(build_before)} the 7000-character cut had "
                  f"already dropped a line solc named")
        if ran:
            repeats = ran - len(audits_with_run_failure)
            print("  the ArbiterNoHarm legend, said once per audit instead of every time:")
            print(f"    {repeats} repeats x {len(_NOHARM_LEGEND)} chars = "
                  f"{repeats * len(_NOHARM_LEGEND):,} chars")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

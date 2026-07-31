#!/usr/bin/env python3
"""How often does each gate actually fire?

The probes prove each gate refuses what it must and admits what it must not refuse. They
say nothing about whether it was ever needed, and a gate that never fires in a real audit
is dead weight carried in the name of soundness.

That could not be answered from the record at all. `trace` holds what the agent SENT --
its messages and tool calls -- and every refusal is text the harness sent BACK, which was
never persisted anywhere. A first version of this script scanned the transcripts and
reported that eleven of fourteen gates had never fired on any audit. They had; the
instrument could not see them, and a measurement that cannot distinguish "never happened"
from "not recorded" is worse than no measurement.

So `dispatch` now classifies each refusal as it hands it to the agent and the counts land
in the outcome. Runs recorded before that show `--` rather than a zero, because those two
are not the same thing.

    scripts/gate_firing.py [run ...]
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.tools import REFUSAL_SIGNATURES  # noqa: E402

RUNS = Path("runs")


def main() -> int:
    runs = sys.argv[1:] or [p.name.replace(".results.jsonl", "")
                            for p in sorted(RUNS.glob("*.results.jsonl"))]
    runs = [r for r in runs if (RUNS / f"{r}.results.jsonl").is_file()]
    if not runs:
        print("no results under runs/")
        return 2

    per_run: dict[str, Counter[str]] = {}
    instrumented: dict[str, bool] = {}
    samples: dict[str, set[str]] = {g: set() for g in REFUSAL_SIGNATURES}

    for run in runs:
        c: Counter[str] = Counter()
        seen_field = False
        for line in (RUNS / f"{run}.results.jsonl").read_text(
                encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            ref = (row.get("outcome") or {}).get("refusals")
            if ref is None:
                continue
            seen_field = True
            for gate, n in ref.items():
                c[gate] += n
                samples[gate].add(f"{run}:{row.get('sample_id')}")
        per_run[run] = c
        instrumented[run] = seen_field

    live = [r for r in runs if instrumented[r]]
    old = [r for r in runs if not instrumented[r]]

    if not live:
        print("None of these runs carry refusal counts. They predate the instrument;")
        print("their transcripts do not record what the harness said back, so the")
        print("question cannot be answered from them at all.")
        print(f"\nruns without the field: {', '.join(old)}")
        return 1

    width = max(len(g) for g in REFUSAL_SIGNATURES) + 2
    print(f"{'gate':<{width}}{'fired':>8}{'samples':>9}   " +
          "".join(f"{r[:11]:>12}" for r in live))
    print("-" * (width + 17 + 12 * len(live)))
    totals = Counter()
    for gate in REFUSAL_SIGNATURES:
        for r in live:
            totals[gate] += per_run[r].get(gate, 0)
        row = "".join(f"{per_run[r].get(gate, 0):>12}" for r in live)
        print(f"{gate:<{width}}{totals[gate]:>8}{len(samples[gate]):>9}   {row}")

    dead = [g for g in REFUSAL_SIGNATURES if totals[g] == 0]
    print(f"\n{len(REFUSAL_SIGNATURES) - len(dead)} of {len(REFUSAL_SIGNATURES)} "
          f"fired at least once, over {len(live)} instrumented run(s).")
    if dead:
        print("did not fire:")
        for g in dead:
            print("   ", g)
        print("  On this evaluation set and this model. Not evidence that the gate is "
              "unnecessary --\n  evidence that nothing here provoked it.")
    if old:
        print(f"\nnot instrumented, shown as absent rather than zero: {', '.join(old)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

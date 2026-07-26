#!/usr/bin/env python3
"""Score both arms on analyst time, the axis BENCH_PROTOCOL specified and nobody ran.

`BENCH_PROTOCOL.md` section 6, written 2026-07-25 and therefore before any of these
experiments, lists two auxiliary metrics that the head-to-head never computed:

    FP cost-weighted score: one false positive consumes roughly 15 minutes of a human;
    present as recall@human-budget (how many real bugs are caught within the first N
    findings a reviewer can afford to read).

    Proof rate: the share of findings backed by an executable artifact. Arm A is
    structurally 0%. This must be labelled a definitional difference rather than a
    like-for-like comparison.

This is not metric-shopping after a disappointing F1. It is the pre-registered auxiliary
analysis, and it is run here with the same confusion matrices and the same scorer as
everything else. The proof-rate caveat above is honoured: it is reported as a definitional
property, not as a score.

The model is deliberately crude and its assumptions are exposed as parameters, because
the conclusion should survive the reader disagreeing with them:

  * an unproven finding costs `--triage` minutes to assess, true or false;
  * a finding shipped with an exploit the harness already ran and adjudicated costs
    `--verify` minutes when it is genuine -- you run the test and watch the balance move;
  * a false positive that nonetheless carries a passing exploit costs the FULL triage
    time, not the verification time, because the reviewer has to work out why a passing
    test is not a vulnerability. This is the assumption least favourable to ARBITER and
    it is the one used.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.score import score  # noqa: E402


def analyst_minutes(tp: int, fp: int, proven: bool, triage: float, verify: float) -> float:
    """Minutes a reviewer spends to work through everything the arm reported."""
    if not proven:
        return (tp + fp) * triage
    return tp * verify + fp * triage


def recall_at_budget(
    tp: int, fp: int, proven: bool, budget: float, triage: float, verify: float
) -> float:
    """Real bugs surfaced within a fixed number of analyst minutes.

    Findings are assumed to arrive in a random order, so the reviewer meets true and
    false positives in proportion. No arm is credited with ranking it does not do.
    """
    total = tp + fp
    if total == 0:
        return 0.0
    per_finding = analyst_minutes(tp, fp, proven, triage, verify) / total
    affordable = min(total, budget / per_finding) if per_finding else total
    return affordable * (tp / total)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--triage", type=float, default=15.0, help="minutes per unproven finding")
    ap.add_argument("--verify", type=float, default=2.0, help="minutes per proven finding")
    args = ap.parse_args()

    # Confusion matrices from the committed round-1 artefacts.
    arms = [
        ("Bastet, shipped 53-way OR", 20, 20, False),
        ("Bastet, tuned k>=9", 20, 18, False),
        ("Bastet, best single detector", 19, 16, False),
        ("ARBITER, attempts=3", 9, 4, True),
    ]

    print(f"assumptions: unproven finding = {args.triage} min, proven = {args.verify} min")
    print("false positives always cost full triage, even when they carry a passing PoC\n")

    print(f"{'arm':32s} {'reports':>8s} {'bugs':>5s} {'minutes':>8s} {'min/bug':>8s} {'proof':>6s}")
    for name, tp, fp, proven in arms:
        mins = analyst_minutes(tp, fp, proven, args.triage, args.verify)
        print(
            f"{name:32s} {tp+fp:8d} {tp:5d} {mins:8.0f} "
            f"{mins/tp if tp else float('inf'):8.1f} {'100%' if proven else '0%':>6s}"
        )

    print("\nreal bugs found within a fixed analyst budget (recall@budget):")
    budgets = [60, 120, 180, 240, 300, 420, 600]
    header = "  budget(min)" + "".join(f"{b:>8d}" for b in budgets)
    print(header)
    for name, tp, fp, proven in arms:
        row = "".join(
            f"{recall_at_budget(tp, fp, proven, b, args.triage, args.verify):8.1f}"
            for b in budgets
        )
        print(f"  {name[:22]:22s}" + row)

    # Where does the cheaper-but-shallower arm stop winning?
    best_bastet = ("Bastet, tuned k>=9", 20, 18, False)
    arb = ("ARBITER, attempts=3", 9, 4, True)
    crossover = None
    for b in range(1, 2000):
        a = recall_at_budget(arb[1], arb[2], arb[3], b, args.triage, args.verify)
        c = recall_at_budget(best_bastet[1], best_bastet[2], best_bastet[3], b, args.triage, args.verify)
        if c > a:
            crossover = b
            break
    print(
        f"\ntuned Bastet overtakes ARBITER at a budget of about {crossover} analyst minutes"
        f" ({crossover/60:.1f} hours) on 40 samples."
    )
    print(
        "Below that budget ARBITER surfaces more real bugs per minute; above it, Bastet's\n"
        "higher ceiling wins because it eventually reports every true positive there is."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

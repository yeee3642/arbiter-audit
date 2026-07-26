#!/usr/bin/env python3
"""Give Bastet a fairly tuned decision threshold before claiming to beat it.

The head-to-head scored Bastet on its own shipped rule -- positive iff any of 53
detectors fires -- which is a 53-way OR and is why its measured true-negative count is 0.
An adversarial review pointed out that this leaves the baseline untuned: nobody checked
whether a single well-chosen detector, or a "k of 53 must agree" vote, does better. If
one does, then the comparison was against a strawman configuration rather than against
the best Bastet available.

This reconstructs both from the committed run summary. Per-detector fire rates are exact
counts in disguise: with 20 vulnerable and 20 patched samples, `fires_on_vuln` * 20 is
that detector's true positives and `fires_on_safe` * 20 is its false positives, so every
single-detector confusion matrix is recoverable without re-running anything.

The k-of-N vote needs per-sample rows and cannot be reconstructed from aggregates, which
is itself a finding: `h2h-bastet.jobs.jsonl` holds them and was never committed. When it
is, `--jobs` computes the full threshold sweep.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.score import Confusion, constant_no_baseline, constant_yes_baseline, score  # noqa: E402


def single_detector_table(summary: dict, n_vuln: int, n_safe: int) -> list[dict]:
    """Recover each detector's confusion matrix from its fire rates."""
    rows = []
    for name, rates in (summary.get("detector_fire_rates") or {}).items():
        tp = round(rates["fires_on_vuln"] * n_vuln)
        fp = round(rates["fires_on_safe"] * n_safe)
        c = Confusion(tp=tp, tn=n_safe - fp, fp=fp, fn=n_vuln - tp)
        rows.append({"detector": name, **c.as_dict()})
    return sorted(rows, key=lambda r: -r["mcc"])


def vote_sweep(jobs_path: Path, truth: dict[str, str]) -> list[dict]:
    """Score 'at least k detectors fired' for every k. Needs the per-sample rows."""
    fired: dict[str, int] = {s: 0 for s in truth}
    for line in jobs_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("n_findings"):
            fired[row["sample"]] = fired.get(row["sample"], 0) + 1
    out = []
    for k in range(1, max(fired.values(), default=1) + 1):
        preds = {s: ("vuln" if fired.get(s, 0) >= k else "safe") for s in truth}
        c = score(preds, truth)
        out.append({"k": k, **c.as_dict()})
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", type=Path, required=True)
    ap.add_argument("--evalset", type=Path, required=True)
    ap.add_argument("--jobs", type=Path, help="h2h-bastet.jobs.jsonl, if committed")
    args = ap.parse_args()

    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    ev = json.loads(args.evalset.read_text(encoding="utf-8"))
    truth = {i["id"]: i["label"] for i in ev["items"]}
    n_vuln = sum(1 for v in truth.values() if v == "vuln")
    n_safe = len(truth) - n_vuln

    print(f"evalset: {n_vuln} vulnerable / {n_safe} patched\n")
    for name, c in (
        ("constant 'vulnerable'", constant_yes_baseline(truth)),
        ("constant 'safe'", constant_no_baseline(truth)),
    ):
        d = c.as_dict()
        print(
            f"  {name:24s} F1={d['f1']:.4f} MCC={d['mcc']:+.3f} "
            f"spec={d['specificity']:.3f}"
        )

    shipped = summary.get("scored", {}).get("runs", [{}])[0]
    if shipped:
        print(
            f"  {'Bastet as shipped (OR)':24s} F1={shipped['f1']:.4f} "
            f"MCC={shipped['mcc']:+.3f} spec={shipped['specificity']:.3f}"
        )

    rows = single_detector_table(summary, n_vuln, n_safe)
    print(f"\nBest single detectors of {len(rows)}, by MCC:")
    for r in rows[:8]:
        print(
            f"  {r['detector'][:46]:48s} TP={r['TP']:2d} FP={r['FP']:2d} "
            f"F1={r['f1']:.4f} MCC={r['mcc']:+.3f}"
        )

    if rows:
        best = rows[0]
        print(
            f"\nBEST SINGLE DETECTOR: {best['detector']}\n"
            f"  F1={best['f1']:.4f}  MCC={best['mcc']:+.3f}  "
            f"specificity={best['specificity']:.3f}"
        )

    if args.jobs and args.jobs.exists():
        print("\n'at least k detectors fired' sweep:")
        for r in vote_sweep(args.jobs, truth):
            print(
                f"  k={r['k']:2d}  TP={r['TP']:2d} TN={r['TN']:2d} FP={r['FP']:2d} "
                f"FN={r['FN']:2d}  F1={r['f1']:.4f}  MCC={r['mcc']:+.3f}"
            )
    else:
        print(
            "\nk-of-N sweep unavailable: per-sample rows were never committed. "
            "Pass --jobs runs/h2h-bastet.jobs.jsonl once that file is in the repo."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

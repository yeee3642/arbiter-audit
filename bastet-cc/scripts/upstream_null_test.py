#!/usr/bin/env python3
"""Does upstream's pipeline beat answering "vulnerable" to everything?

`instrument_audit.py` showed the floor analytically: at 50/50 class balance a constant
"yes" scores F1 0.6667, because precision is pinned at 0.5 and recall is perfect. That
argument holds for any detector; it says nothing about this one.

This measures the actual gap. Upstream's own `cli/main.py eval`, its own demo detector,
against `ais3/nemotron-3-ultra-550b`, repeated. Each repetition draws a fresh sample --
upstream calls `.sample()` without `random_state`, so repeated runs are independent
draws from the same protocol, which is exactly the variance a single published number
hides.

The comparison is one-sample: every run is scored against the same analytic floor, so
a paired test would be comparing a distribution against a constant. A bootstrap over
runs gives the CI on the mean gap.

Two caveats belong in any writeup of this number: it covers one tag with one detector,
and it uses the Kaggle corpus rather than the `dataset_0831` corpus upstream published
against. The floor argument generalises; this measurement does not, on its own.

Usage:
    python scripts/upstream_null_test.py --runs 10        # run and analyse
    python scripts/upstream_null_test.py --analyse-only   # re-analyse stored results
"""

from __future__ import annotations

import argparse
import json
import random
import re
import statistics as st
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bastet_cc.evaluate import Confusion  # noqa: E402

UPSTREAM = Path("/home/e0pwr/ais3-2026/upstream-bastet")
OUT = Path(__file__).resolve().parents[1] / "runs" / "upstream_null"
RESULTS = OUT / "runs.jsonl"

TAG = "Slippage"
WEBHOOK = "http://localhost:5678/webhook/slippage_minAmount"
SAMPLE_SIZE = 9        # the balanced maximum for this tag: min(size, |tagged|, |untagged|)
MODEL = "ais3/nemotron-3-ultra-550b"

METRIC_RE = re.compile(r"^(accuracy|precision|recall|f1):\s*([0-9.]+|nan)", re.M)
CELL_RE = re.compile(r"\|\s*(True Positive|True Negative|False Positive|False Negative)\s*\|\s*(\d+)")


def run_once(index: int) -> dict | None:
    cmd = [
        str(UPSTREAM / ".venv/bin/python"), "cli/main.py", "eval",
        "--csv-path", "./dataset/dataset.csv",
        "--tag", TAG,
        "--n8n-workflow-webhook-url", WEBHOOK,
        "--size", str(SAMPLE_SIZE),
        "--dataset-root", "/home/e0pwr/ais3-2026/data/ex/train/",
    ]
    proc = subprocess.run(
        cmd, cwd=UPSTREAM, capture_output=True, text=True,
        env={"PYTHONPATH": "cli", "PATH": "/usr/bin:/bin"},
    )
    blob = proc.stdout + proc.stderr
    cells = {k: int(v) for k, v in CELL_RE.findall(blob)}
    if len(cells) != 4:
        print(f"  run {index}: could not parse confusion matrix")
        return None
    cm = Confusion(
        tp=cells["True Positive"], tn=cells["True Negative"],
        fp=cells["False Positive"], fn=cells["False Negative"],
    )
    row = {
        "run": index, "tag": TAG, "model": MODEL, "sample_size": SAMPLE_SIZE,
        "tp": cm.tp, "tn": cm.tn, "fp": cm.fp, "fn": cm.fn,
        "precision": cm.precision, "recall": cm.recall,
        "f1": cm.f1, "accuracy": cm.accuracy,
    }
    print(f"  run {index}: TP={cm.tp} TN={cm.tn} FP={cm.fp} FN={cm.fn}  "
          f"F1={cm.f1:.4f}  acc={cm.accuracy:.4f}")
    return row


def bootstrap_ci(values: list[float], reps: int = 10_000, seed: int = 20260725):
    rng = random.Random(seed)
    n = len(values)
    means = sorted(
        sum(values[rng.randrange(n)] for _ in range(n)) / n for _ in range(reps)
    )
    return means[int(0.025 * reps)], means[int(0.975 * reps)]


def analyse() -> int:
    if not RESULTS.exists():
        print(f"no results at {RESULTS}")
        return 1
    rows = [json.loads(l) for l in RESULTS.read_text().splitlines() if l.strip()]
    if not rows:
        print("no runs recorded")
        return 1

    pos = rows[0]["sample_size"]
    neg = rows[0]["sample_size"]
    floor = Confusion(tp=pos, fp=neg, fn=0, tn=0)

    f1 = [r["f1"] for r in rows if r["f1"] is not None]
    acc = [r["accuracy"] for r in rows if r["accuracy"] is not None]
    prec = [r["precision"] for r in rows if r["precision"] is not None]
    rec = [r["recall"] for r in rows if r["recall"] is not None]

    gaps_f1 = [v - floor.f1 for v in f1]
    gaps_acc = [v - floor.accuracy for v in acc]

    print()
    print(f"upstream `cli/main.py eval` -- tag={TAG}, detector=slippage_min_amount")
    print(f"model={MODEL}, {pos} positive / {neg} negative, n={len(rows)} independent draws")
    print()
    print(f"{'':<24}{'mean':>9}{'sd':>9}{'min':>9}{'max':>9}")
    for name, vals in [("precision", prec), ("recall", rec),
                       ("F1", f1), ("accuracy", acc)]:
        sd = st.stdev(vals) if len(vals) > 1 else 0.0
        print(f"{name:<24}{st.mean(vals):>9.4f}{sd:>9.4f}"
              f"{min(vals):>9.4f}{max(vals):>9.4f}")

    print()
    print(f"{'constant-yes floor':<24}{'F1':>9}{'accuracy':>10}")
    print(f"{'':<24}{floor.f1:>9.4f}{floor.accuracy:>10.4f}")

    print()
    for name, gaps in [("F1", gaps_f1), ("accuracy", gaps_acc)]:
        m = st.mean(gaps)
        lo, hi = bootstrap_ci(gaps)
        verdict = (
            "excludes zero -- real signal" if lo > 0 else
            "excludes zero -- worse than the floor" if hi < 0 else
            "includes zero -- indistinguishable from the floor"
        )
        print(f"gain over floor, {name:<9} {m:>+8.4f}   95% CI [{lo:+.4f}, {hi:+.4f}]"
              f"   {verdict}")

    spread = max(f1) - min(f1)
    published_gap = abs(0.7742 - 0.6809)
    print()
    print(f"run-to-run F1 spread (unseeded)          : {spread:.4f}")
    print(f"gap between upstream's two published F1s : {published_gap:.4f}")
    if published_gap < spread:
        print("  -- the published gap is inside this protocol's own noise, so those two")
        print("     numbers are not distinguishable by the instrument that produced them.")

    summary = {
        "tag": TAG, "model": MODEL, "n_runs": len(rows),
        "sample_pos": pos, "sample_neg": neg,
        "mean_f1": st.mean(f1), "sd_f1": st.stdev(f1) if len(f1) > 1 else 0.0,
        "mean_accuracy": st.mean(acc),
        "floor_f1": floor.f1, "floor_accuracy": floor.accuracy,
        "gain_f1": st.mean(gaps_f1), "gain_f1_ci95": list(bootstrap_ci(gaps_f1)),
        "gain_accuracy": st.mean(gaps_acc),
        "gain_accuracy_ci95": list(bootstrap_ci(gaps_acc)),
        "f1_spread": spread,
        "caveats": [
            "single tag (Slippage), single detector (slippage_min_amount)",
            "Kaggle train corpus, not the dataset_0831 corpus upstream published on",
        ],
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\nWrote {OUT / 'summary.json'}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=0)
    ap.add_argument("--analyse-only", action="store_true")
    args = ap.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    if args.runs and not args.analyse_only:
        start = len(RESULTS.read_text().splitlines()) if RESULTS.exists() else 0
        print(f"running upstream eval {args.runs}x (each ~12 min)")
        with RESULTS.open("a") as fh:
            for i in range(start, start + args.runs):
                row = run_once(i)
                if row:
                    fh.write(json.dumps(row) + "\n")
                    fh.flush()
    return analyse()


if __name__ == "__main__":
    sys.exit(main())

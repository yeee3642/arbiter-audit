#!/usr/bin/env python3
"""Report a run exactly as PREREGISTRATION_vloss4.md said it would be reported.

Full confusion matrix, never a selected metric. Precision, recall and MCC together,
because precision alone is unfalsifiable -- a gate that refuses everything scores 1.000.
A bootstrap interval on the difference against the recorded arm, so "not separated at this
sample size" can be said when that is the truth. Every false positive attributed to the
predicate that produced it. And what the change cost in true positives.

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from pathlib import Path


def load(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def confusion(rows: list[dict]) -> tuple[int, int, int, int]:
    tp = tn = fp = fn = 0
    for row in rows:
        truth, pred = row.get("truth"), row.get("predicted")
        if truth == "vuln" and pred == "vuln":
            tp += 1
        elif truth == "safe" and pred == "safe":
            tn += 1
        elif truth == "safe" and pred == "vuln":
            fp += 1
        else:
            fn += 1
    return tp, tn, fp, fn


def rates(tp: int, tn: int, fp: int, fn: int) -> dict[str, float]:
    n = tp + tn + fp + fn
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    denom = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    return {
        "accuracy": (tp + tn) / n if n else 0.0,
        "precision": prec,
        "recall": rec,
        "specificity": tn / (tn + fp) if (tn + fp) else 0.0,
        "f1": 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0,
        "mcc": ((tp * tn - fp * fn) / denom) if denom else 0.0,
    }


def winning_predicate(row: dict) -> str:
    for poc in (row.get("outcome") or {}).get("pocs") or []:
        if poc.get("passed") and poc.get("adjudicated"):
            return str(poc.get("predicate") or "?")
    return "-"


def bootstrap_delta(a: list[dict], b: list[dict], metric: str, draws: int = 20000) -> str:
    """Paired bootstrap over samples present in both arms."""
    by_id_a = {r["sample_id"]: r for r in a}
    by_id_b = {r["sample_id"]: r for r in b}
    shared = sorted(set(by_id_a) & set(by_id_b))
    if not shared:
        return "no shared samples"
    rng = random.Random(20260728)
    deltas = []
    for _ in range(draws):
        picked = [shared[rng.randrange(len(shared))] for _ in shared]
        va = rates(*confusion([by_id_a[s] for s in picked]))[metric]
        vb = rates(*confusion([by_id_b[s] for s in picked]))[metric]
        deltas.append(vb - va)
    deltas.sort()
    lo, hi = deltas[int(0.025 * draws)], deltas[int(0.975 * draws)]
    mid = sum(deltas) / len(deltas)
    verdict = "excludes zero" if (lo > 0 or hi < 0) else "INCLUDES ZERO"
    return f"{mid:+.3f}  [{lo:+.3f}, {hi:+.3f}]  {verdict}   (n={len(shared)})"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm-a", type=Path, required=True, help="recorded baseline results")
    ap.add_argument("--arm-b", type=Path, required=True, help="the run being reported")
    args = ap.parse_args()

    a, b = load(args.arm_a), load(args.arm_b)
    ca, cb = confusion(a), confusion(b)
    ra, rb = rates(*ca), rates(*cb)

    print(f"arm A  {args.arm_a.stem:16s} {len(a)} samples")
    print(f"arm B  {args.arm_b.stem:16s} {len(b)} samples\n")

    print(f"{'':14s} {'arm A':>10s} {'arm B':>10s}")
    for label, i in (("TP", 0), ("TN", 1), ("FP", 2), ("FN", 3)):
        print(f"{label:14s} {ca[i]:>10d} {cb[i]:>10d}")
    for key in ("accuracy", "precision", "recall", "specificity", "f1", "mcc"):
        print(f"{key:14s} {ra[key]:>10.3f} {rb[key]:>10.3f}")

    print("\npaired bootstrap on the difference (B - A):")
    for metric in ("precision", "recall", "f1", "mcc"):
        print(f"  {metric:12s} {bootstrap_delta(a, b, metric)}")

    print("\nfalse positives in arm B, by the predicate that produced them:")
    fps = [r for r in b if r.get("truth") == "safe" and r.get("predicted") == "vuln"]
    for row in fps:
        print(f"  {row['sample_id'][:46]:48s} {winning_predicate(row)}")
    counts = Counter(winning_predicate(r) for r in fps)
    print(f"  -> {dict(counts) if counts else 'none'}")

    print("\ntrue positives in arm B, by predicate:")
    tps = [r for r in b if r.get("truth") == "vuln" and r.get("predicted") == "vuln"]
    print(f"  {dict(Counter(winning_predicate(r) for r in tps))}")

    a_ids = {r["sample_id"] for r in a if r.get("predicted") == "vuln" and r.get("truth") == "vuln"}
    b_ids = {r["sample_id"] for r in tps}
    lost, gained = sorted(a_ids - b_ids), sorted(b_ids - a_ids)
    print(f"\ntrue positives arm A found and arm B did not ({len(lost)}):")
    for s in lost:
        print(f"  {s}")
    print(f"true positives arm B found and arm A did not ({len(gained)}):")
    for s in gained:
        print(f"  {s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

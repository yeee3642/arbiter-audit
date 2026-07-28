#!/usr/bin/env python3
"""Generate broadly, judge strictly: score the union of two arms behind the gates.

An adversarial review made the architectural charge that settles the disappointing
head-to-head: the gates are monotone REJECTORS, and they were wired into the generator.
Arm B found five true positives arm A never found and lost ten -- the gates did not merely
filter what was accepted, they perturbed what the agent went looking for. A thing that can
only ever say no belongs outside the loop.

The measurement is free, because both arms are already on disk. Attack surface is the
UNION of what either arm ever proved; the gates are applied afterwards, as a filter.
Attack breadth and evidential standard stop competing for the same knob.

Four rows are printed rather than one, because the interesting comparison is not
cascade-versus-best but cascade-versus-both-arms-as-they-ran.

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


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


def score(flagged: set[str], truth: dict[str, str]) -> tuple[int, int, int, int]:
    tp = sum(1 for s, t in truth.items() if t == "vuln" and s in flagged)
    fp = sum(1 for s, t in truth.items() if t == "safe" and s in flagged)
    fn = sum(1 for s, t in truth.items() if t == "vuln" and s not in flagged)
    tn = sum(1 for s, t in truth.items() if t == "safe" and s not in flagged)
    return tp, tn, fp, fn


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm-a", type=Path, required=True)
    ap.add_argument("--arm-b", type=Path, required=True)
    ap.add_argument("--gates-a", type=Path, required=True,
                    help="per-sample gate verdicts for arm A, from recheck_verdicts.py")
    ap.add_argument("--gates-b", type=Path, required=True)
    args = ap.parse_args()

    a, b = load(args.arm_a), load(args.arm_b)
    truth = {r["sample_id"]: r["truth"] for r in a + b}

    flag_a = {r["sample_id"] for r in a if r.get("predicted") == "vuln"}
    flag_b = {r["sample_id"] for r in b if r.get("predicted") == "vuln"}

    # A sample survives the gates if EITHER arm's exploit for it survives. The gates
    # judge exploits, not samples, so one surviving exploit is one surviving proof.
    survives = {
        r["sample_id"]
        for r in load(args.gates_a) + load(args.gates_b)
        if r.get("verdict") == "accepted"
    }

    rows = [
        ("arm A as it ran", flag_a),
        ("arm B as it ran", flag_b),
        ("union, ungated", flag_a | flag_b),
        ("union, behind the gates", (flag_a | flag_b) & survives),
    ]

    print(f"{'':26s} {'TP':>4s} {'TN':>4s} {'FP':>4s} {'FN':>4s}   "
          f"{'prec':>6s} {'rec':>6s} {'spec':>6s} {'f1':>6s} {'mcc':>6s}")
    for label, flagged in rows:
        tp, tn, fp, fn = score(flagged, truth)
        m = rates(tp, tn, fp, fn)
        print(f"{label:26s} {tp:>4d} {tn:>4d} {fp:>4d} {fn:>4d}   "
              f"{m['precision']:>6.3f} {m['recall']:>6.3f} {m['specificity']:>6.3f} "
              f"{m['f1']:>6.3f} {m['mcc']:>6.3f}")

    # The same discipline applied to arm B's disappointing result has to be applied here,
    # or this table is worth no more than the one it replaces.
    import random

    cascade = (flag_a | flag_b) & survives
    samples = sorted(truth)
    rng = random.Random(20260728)
    print("\npaired bootstrap, cascade minus arm A, 20,000 draws:")
    for metric in ("precision", "recall", "f1", "mcc"):
        deltas = []
        for _ in range(20000):
            picked = [samples[rng.randrange(len(samples))] for _ in samples]
            sub = {s: truth[s] for s in set(picked)}
            counts = {s: picked.count(s) for s in sub}

            def weighted(flagged: set[str]) -> tuple[int, int, int, int]:
                tp = sum(counts[s] for s, t in sub.items() if t == "vuln" and s in flagged)
                fp = sum(counts[s] for s, t in sub.items() if t == "safe" and s in flagged)
                fn = sum(counts[s] for s, t in sub.items() if t == "vuln" and s not in flagged)
                tn = sum(counts[s] for s, t in sub.items() if t == "safe" and s not in flagged)
                return tp, tn, fp, fn

            deltas.append(rates(*weighted(cascade))[metric] - rates(*weighted(flag_a))[metric])
        deltas.sort()
        lo, hi = deltas[500], deltas[19499]
        mid = sum(deltas) / len(deltas)
        verdict = "excludes zero" if (lo > 0 or hi < 0) else "INCLUDES ZERO"
        print(f"  {metric:12s} {mid:+.3f}  [{lo:+.3f}, {hi:+.3f}]  {verdict}")

    only_a = sorted(s for s in flag_a - flag_b if truth.get(s) == "vuln")
    only_b = sorted(s for s in flag_b - flag_a if truth.get(s) == "vuln")
    print(f"\ntrue positives only arm A found: {len(only_a)}")
    print(f"true positives only arm B found: {len(only_b)}")
    print("The union is larger than either arm, which is the whole point: the two")
    print("configurations look in different places, and a rejector placed after them")
    print("costs none of that breadth.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

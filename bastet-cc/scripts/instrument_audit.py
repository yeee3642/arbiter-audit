#!/usr/bin/env python3
"""Audit the measuring instrument, not the thing being measured.

Every published number for this benchmark -- upstream's own and anything we produce --
is read off one evaluation protocol: sample findings for a tag, scan each repository,
score a confusion matrix. Before comparing detectors on that scale, it is worth asking
what the scale can and cannot register.

Four questions, none of which need a model to answer:

  ceiling    What does a predictor handed the ground truth score? A sound protocol
             returns 1.0. (Measured separately in e6_scorer_forensics.py; summarised
             here.)
  floor      What does a predictor that ignores the input score? At 50/50 balance,
             answering "vulnerable" every time earns F1 0.667, because precision is
             pinned at 0.5 and recall is perfect. Any system's real contribution is the
             distance above that floor, not its absolute F1.
  stability  Upstream calls `.sample()` with no `random_state`. How far does the same
             predictor's score move between draws?
  metric     F1, accuracy, balanced accuracy and MCC disagree about whether a
             constant answer is good. Which one a paper reports changes the story.

The floor is the uncomfortable one. Upstream's README reports F1 0.6809 from
TP=16 TN=27 FP=2 FN=13 -- a balanced 29/29 draw. The constant-"yes" predictor scores
0.6667 on that same draw. The gap is what 56 hand-written detectors and 172,346
characters of prompt bought.

That is not purely an indictment. F1 at 50/50 balance is a poor choice of metric
precisely because it flatters constant answers; on accuracy the same system reads 0.741
against a 0.500 floor. Both numbers are correct and they tell opposite stories, which is
the finding: the reported improvement is an artefact of metric choice as much as of
detection quality.

Run:  python scripts/instrument_audit.py
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bastet_cc.evaluate import Confusion  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "runs" / "instrument"

# Upstream's own published results. The slide deck and the repository disagree, and the
# disagreement is itself informative: same workflow, same tag, different class balance.
PUBLISHED = {
    "README (github, current)": Confusion(tp=16, tn=27, fp=2, fn=13),
    "CyberSec / ETH Taipei 2025 slides": Confusion(tp=12, tn=27, fp=2, fn=5),
}


def balanced_accuracy(c: Confusion) -> float | None:
    pos, neg = c.tp + c.fn, c.tn + c.fp
    if not pos or not neg:
        return None
    return 0.5 * (c.tp / pos + c.tn / neg)


def mcc(c: Confusion) -> float | None:
    num = c.tp * c.tn - c.fp * c.fn
    den = math.sqrt((c.tp + c.fp) * (c.tp + c.fn) * (c.tn + c.fp) * (c.tn + c.fn))
    return num / den if den else None


def constant_yes(pos: int, neg: int) -> Confusion:
    return Confusion(tp=pos, fp=neg, fn=0, tn=0)


def constant_no(pos: int, neg: int) -> Confusion:
    return Confusion(tp=0, fp=0, fn=pos, tn=neg)


def coin_flip(pos: int, neg: int) -> Confusion:
    """Expected cell counts for an unbiased coin, rounded to whole samples."""
    return Confusion(tp=pos // 2, fn=pos - pos // 2, fp=neg // 2, tn=neg - neg // 2)


def fmt(v: float | None, w: int = 8, p: int = 4) -> str:
    return f"{'n/a':>{w}}" if v is None else f"{v:>{w}.{p}f}"


def metric_row(name: str, c: Confusion) -> dict:
    return {
        "predictor": name,
        "tp": c.tp, "fp": c.fp, "fn": c.fn, "tn": c.tn,
        "n": c.n,
        "precision": c.precision,
        "recall": c.recall,
        "f1": c.f1,
        "accuracy": c.accuracy,
        "balanced_accuracy": balanced_accuracy(c),
        "mcc": mcc(c),
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []

    print("=" * 78)
    print("FLOOR -- what a predictor that never reads the code scores")
    print("=" * 78)

    for label, published in PUBLISHED.items():
        pos, neg = published.tp + published.fn, published.tn + published.fp
        print(f"\n{label}")
        print(f"  class balance: {pos} positive / {neg} negative")
        print(f"  {'predictor':<26}{'F1':>9}{'acc':>9}{'bal.acc':>9}{'MCC':>9}")

        entries = [
            (f"{label} :: published", published),
            (f"{label} :: constant yes", constant_yes(pos, neg)),
            (f"{label} :: constant no", constant_no(pos, neg)),
            (f"{label} :: coin flip", coin_flip(pos, neg)),
        ]
        for name, c in entries:
            short = name.split(":: ")[1]
            print(f"  {short:<26}{fmt(c.f1, 9)}{fmt(c.accuracy, 9)}"
                  f"{fmt(balanced_accuracy(c), 9)}{fmt(mcc(c), 9)}")
            rows.append(metric_row(name, c))

        yes = constant_yes(pos, neg)
        d_f1 = published.f1 - yes.f1
        d_acc = published.accuracy - yes.accuracy
        print(f"  {'gain over constant yes':<26}{d_f1:>+9.4f}{d_acc:>+9.4f}")

    print()
    print("=" * 78)
    print("METRIC -- the same system, four scales, two conclusions")
    print("=" * 78)
    readme = PUBLISHED["README (github, current)"]
    yes = constant_yes(readme.tp + readme.fn, readme.tn + readme.fp)
    print(f"\n{'metric':<22}{'published':>11}{'constant yes':>14}{'gain':>10}"
          f"{'  reading':<10}")
    for mname, fn in [
        ("F1", lambda c: c.f1),
        ("accuracy", lambda c: c.accuracy),
        ("balanced accuracy", balanced_accuracy),
        ("MCC", mcc),
    ]:
        a, b = fn(readme), fn(yes)
        if a is None or b is None:
            continue
        gain = a - b
        verdict = "barely above floor" if gain < 0.05 else "clearly above floor"
        print(f"{mname:<22}{a:>11.4f}{b:>14.4f}{gain:>+10.4f}  {verdict}")

    print("\nThe reported improvement depends on which scale is used to report it.")
    print("Upstream reports F1.")

    # Sensitivity: how the floor moves with class balance, holding the detector fixed.
    print()
    print("=" * 78)
    print("BALANCE -- the floor is a function of class balance, not of the detector")
    print("=" * 78)
    print(f"\n{'positives':>10}{'negatives':>11}{'constant-yes F1':>18}")
    bal_rows = []
    for pos, neg in [(29, 29), (17, 29), (10, 40), (40, 10), (5, 45)]:
        c = constant_yes(pos, neg)
        print(f"{pos:>10}{neg:>11}{c.f1:>18.4f}")
        bal_rows.append({"pos": pos, "neg": neg, "constant_yes_f1": c.f1})
    print("\nUpstream's sampler forces pos == neg via min(size, |tagged|, |untagged|),")
    print("which is exactly the balance where constant-yes scores highest.")

    # Ceiling and stability, carried over from E6 so one artefact holds all four.
    e6 = Path(__file__).resolve().parents[1] / "runs" / "e6" / "e6_summary.json"
    if e6.exists():
        s = json.loads(e6.read_text())
        print()
        print("=" * 78)
        print("CEILING and STABILITY -- from e6_scorer_forensics.py")
        print("=" * 78)
        print(f"\n  perfect predictor, upstream protocol : macro-F1 "
              f"{s['upstream_macro_f1_perfect_predictor']:.4f}")
        print(f"  perfect predictor, repo-level protocol: macro-F1 "
              f"{s['fixed_macro_f1_perfect_predictor']:.4f}")
        print(f"  mean F1 spread across {len(s['seeds'])} seeds   : "
              f"{s['mean_seed_spread_upstream']:.4f}")
        gap = abs(PUBLISHED["CyberSec / ETH Taipei 2025 slides"].f1
                  - PUBLISHED["README (github, current)"].f1)
        print(f"\n  gap between upstream's two published F1 values: {gap:.4f}")
        if gap < s["mean_seed_spread_upstream"]:
            print("  -- smaller than the protocol's own seed-to-seed spread, so the two")
            print("     published numbers are not distinguishable by this instrument.")

    df = pd.DataFrame(rows)
    df.to_csv(OUT / "instrument_audit.csv", index=False)
    pd.DataFrame(bal_rows).to_csv(OUT / "balance_sensitivity.csv", index=False)

    summary = {
        "published": {k: metric_row(k, v) for k, v in PUBLISHED.items()},
        "readme_gain_over_constant_yes": {
            "f1": readme.f1 - yes.f1,
            "accuracy": readme.accuracy - yes.accuracy,
            "mcc": (mcc(readme) or 0) - (mcc(yes) or 0),
        },
    }
    (OUT / "instrument_audit.json").write_text(json.dumps(summary, indent=2))
    print(f"\nWrote {OUT / 'instrument_audit.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

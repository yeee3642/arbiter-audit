#!/usr/bin/env python3
"""E6 -- score a perfect predictor with upstream Bastet's own evaluator.

The construction is deliberately unfair to us and maximally fair to upstream: the
predictor is handed the ground truth. For repository R and tag T it answers "yes"
exactly when R genuinely contains a finding tagged T, and never otherwise. No model,
no heuristic, no threshold. A sound evaluator must return F1 = 1.0.

It does not, and the reason is structural. `cli/commands/evaluate/eval.py` draws and
labels its sample one *finding row* at a time, then predicts one *repository* at a
time -- it walks `repo_path` and stops at the first file that yields output. Each
repository contributes ~9.2 rows on average, so a repository holding both a `DoS`
finding and a `Reentrancy` finding lands in the positive pool for `DoS` via one row
and the negative pool via the other. The scanner answers once. Whatever it answers,
one of the two rows records an error.

Two independent defects compound in the same function:

  row_untagged = dataset[dataset["tag"] != tag]   # exact inequality selects negatives
  y_true.append(tag in row["tag"])                # substring containment labels them

Tags are comma-separated multi-labels ("Chainlink, Oracle"), so a row tagged
"Slippage, Logic error" is drawn as a negative and then labelled positive. Meanwhile
`row_tagged` uses exact equality, so every multi-tag positive is excluded from the
positive pool entirely -- 25.4% of the corpus.

Run:  python scripts/e6_scorer_forensics.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bastet_cc.evaluate import Confusion, normalize_tag, parse_tags  # noqa: E402

TRAIN_CSV = Path(__file__).resolve().parents[2] / "data" / "train.csv"
OUT_DIR = Path(__file__).resolve().parents[1] / "runs" / "e6"
SAMPLE_SIZE = 100          # upstream's CLI default
SEEDS = range(10)          # upstream draws unseeded; we sweep to expose the variance


def upstream_sample_and_score(
    df: pd.DataFrame,
    tag: str,
    truth: dict[str, set[str]],
    seed: int,
    sample_size: int = SAMPLE_SIZE,
) -> Confusion | None:
    """Replay upstream's sampling, labelling and prediction loop verbatim.

    Mirrors eval.py lines 25-44 (sampling), 61-118 (per-row predict + label) and
    120-122 (confusion matrix), with the scan replaced by an oracle.
    """
    # eval.py:25-26 -- exact string equality on the raw tag cell, both directions.
    row_tagged = df[df["tag"] == tag]
    row_untagged = df[df["tag"] != tag]

    n = min(sample_size, len(row_tagged), len(row_untagged))
    if n == 0:
        return None

    # eval.py:28-33 -- upstream passes no random_state; the seed here only lets us
    # measure how much the missing seed matters.
    picked_tagged = row_tagged.sample(n=n, random_state=seed)
    picked_untagged = row_untagged.sample(n=n, random_state=seed + 10_000)
    combined = pd.concat([picked_tagged, picked_untagged]).sample(
        frac=1, random_state=seed
    )

    y_pred: list[int] = []
    y_true: list[int] = []
    for _, row in combined.iterrows():
        repo = str(row["repo_path"]).strip()

        # The oracle: perfect repository-level knowledge, which is the strongest
        # scanner that could possibly exist.
        predicted = 1 if tag in truth.get(repo, set()) else 0

        # eval.py:96 -- substring containment against the raw cell.
        actual = 1 if tag in str(row["tag"]) else 0

        y_pred.append(predicted)
        y_true.append(actual)

    cm = Confusion()
    for p, a in zip(y_pred, y_true):
        cm.add(bool(p), bool(a))
    return cm


def fixed_sample_and_score(
    df: pd.DataFrame,
    tag: str,
    truth: dict[str, set[str]],
    seed: int,
    sample_size: int = SAMPLE_SIZE,
) -> Confusion | None:
    """Score the same oracle after moving sampling and labelling to repository level.

    One row per repository, labels by set membership over the split tags. Nothing
    else changes -- same oracle, same tag, same corpus.
    """
    positives = sorted(r for r, tags in truth.items() if tag in tags)
    negatives = sorted(r for r, tags in truth.items() if tag not in tags)
    n = min(sample_size, len(positives), len(negatives))
    if n == 0:
        return None

    pos = pd.Series(positives).sample(n=n, random_state=seed).tolist()
    neg = pd.Series(negatives).sample(n=n, random_state=seed + 10_000).tolist()

    cm = Confusion()
    for repo in pos:
        cm.add(tag in truth.get(repo, set()), True)
    for repo in neg:
        cm.add(tag in truth.get(repo, set()), False)
    return cm


def main() -> int:
    df = pd.read_csv(TRAIN_CSV)
    if "status" in df.columns:
        df = df[df["status"].astype(str).str.strip().str.lower() == "done"]

    # Repository -> the set of tags it genuinely carries.
    truth: dict[str, set[str]] = {}
    for repo, raw in zip(df["repo_path"], df["tag"]):
        key = str(repo).strip()
        truth.setdefault(key, set()).update(normalize_tag(t) for t in parse_tags(raw))

    atoms: dict[str, int] = {}
    for tags in truth.values():
        for t in tags:
            atoms[t] = atoms.get(t, 0) + 1
    ranked = sorted(atoms.items(), key=lambda kv: -kv[1])

    rows = []
    for tag, n_pos_repos in ranked:
        if n_pos_repos < 2:
            continue
        ups = [upstream_sample_and_score(df, tag, truth, s) for s in SEEDS]
        fix = [fixed_sample_and_score(df, tag, truth, s) for s in SEEDS]
        ups = [c for c in ups if c is not None]
        fix = [c for c in fix if c is not None]
        if not ups or not fix:
            continue

        def mean(cms: list[Confusion], attr: str) -> float | None:
            vals = [getattr(c, attr) for c in cms]
            vals = [v for v in vals if v is not None]
            return sum(vals) / len(vals) if vals else None

        rows.append({
            "tag": tag,
            "n_pos_repos": n_pos_repos,
            "upstream_f1": mean(ups, "f1"),
            "upstream_precision": mean(ups, "precision"),
            "upstream_recall": mean(ups, "recall"),
            "upstream_f1_min": min(c.f1 for c in ups if c.f1 is not None),
            "upstream_f1_max": max(c.f1 for c in ups if c.f1 is not None),
            "fixed_f1": mean(fix, "f1"),
        })

    out = pd.DataFrame(rows)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out.to_csv(OUT_DIR / "e6_perfect_predictor.csv", index=False)

    print("A PERFECT predictor -- handed the ground truth -- scored by each evaluator")
    print(f"(mean over {len(SEEDS)} seeds; upstream passes no random_state at all)\n")
    print(f"{'tag':<22}{'+repos':>7}{'upstream F1':>13}{'  [min,max]':>16}{'fixed F1':>10}")
    print("-" * 70)
    for r in out.itertuples():
        rng = f"[{r.upstream_f1_min:.3f},{r.upstream_f1_max:.3f}]"
        print(
            f"{r.tag:<22}{r.n_pos_repos:>7}{r.upstream_f1:>13.3f}{rng:>16}"
            f"{r.fixed_f1:>10.3f}"
        )

    macro_up = out["upstream_f1"].mean()
    macro_fix = out["fixed_f1"].mean()
    worst = out.loc[out["upstream_f1"].idxmin()]
    spread = (out["upstream_f1_max"] - out["upstream_f1_min"]).mean()

    print("-" * 70)
    print(f"{'macro-F1':<22}{'':>7}{macro_up:>13.3f}{'':>16}{macro_fix:>10.3f}")
    print()
    print(f"A flawless scanner loses {100 * (1 - macro_up):.1f}% of macro-F1 to the")
    print(f"evaluator alone. Worst tag: {worst.tag} at F1 {worst.upstream_f1:.3f}")
    print(f"(precision {worst.upstream_precision:.3f}, recall {worst.upstream_recall:.3f}).")
    print(f"Mean F1 spread across seeds under upstream sampling: {spread:.3f}")
    print()
    print("Every point below 1.000 is measurement error, not detection error.")
    print(f"Wrote {OUT_DIR / 'e6_perfect_predictor.csv'}")

    (OUT_DIR / "e6_summary.json").write_text(json.dumps({
        "upstream_macro_f1_perfect_predictor": macro_up,
        "fixed_macro_f1_perfect_predictor": macro_fix,
        "mean_seed_spread_upstream": spread,
        "n_tags": len(out),
        "seeds": list(SEEDS),
        "sample_size": SAMPLE_SIZE,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

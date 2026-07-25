#!/usr/bin/env python3
"""Freeze the repository-level TRAIN-SYN / DEV / TEST split.

This runs once, before any detector is synthesised, and never again. Detector
synthesis reads labelled findings, which makes every repository it touches unusable
for measurement -- so the boundary has to exist before the leak can happen, not after.

Splitting by repository rather than by finding is not a preference. A repository holds
9.2 findings on average; splitting rows would put the same codebase on both sides and
every reported number would be memorisation. Upstream's evaluator splits rows.

The allocation is greedy over tags ordered by frequency, because the constraint that
actually binds is the rare tags: `Bridge` has two positive repositories in the entire
corpus, and a random split loses it from some partition entirely. Frequent tags have
slack and can absorb whatever the rare ones force.

Roles, and the leakage rules that follow from them:
  TRAIN-SYN (32)  synthesis source, retrieval knowledge base, routing IDF corpus
  DEV       (10)  threshold and prior calibration, verifier enablement, prompt iteration
  TEST      (12)  read once, on D5, after everything is frozen

Run:  python scripts/make_splits.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bastet_cc.evaluate import normalize_tag, parse_tags  # noqa: E402

SEED = 20260725
TARGET = {"train_syn": 32, "dev": 10, "test": 12}
# Tags this frequent are expected in every split; below the cut we take what we can get.
STRATIFY_TOP_N = 15

DATA = Path(__file__).resolve().parents[2] / "data"
OUT = DATA / "splits.json"


def load_repo_tags(csv_path: Path) -> dict[str, set[str]]:
    df = pd.read_csv(csv_path)
    if "status" in df.columns:
        df = df[df["status"].astype(str).str.strip().str.lower() == "done"]
    repo_tags: dict[str, set[str]] = defaultdict(set)
    for repo, raw in zip(df["repo_path"], df["tag"]):
        repo_tags[str(repo).strip()].update(normalize_tag(t) for t in parse_tags(raw))
    return dict(repo_tags)


def allocate(repo_tags: dict[str, set[str]]) -> dict[str, list[str]]:
    """Assign every repository to exactly one split.

    Each tag is walked in descending frequency and its unassigned positive repositories
    are dealt out to whichever split is furthest below its quota for that tag. Ties go
    to the split with the most remaining capacity overall, which keeps the partition
    sizes near target without a second balancing pass.
    """
    tag_repos: dict[str, list[str]] = defaultdict(list)
    for repo, tags in repo_tags.items():
        for t in tags:
            tag_repos[t].append(repo)
    for t in tag_repos:
        tag_repos[t].sort()

    ranked = sorted(tag_repos.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    names = list(TARGET)
    total = sum(TARGET.values())
    share = {s: TARGET[s] / total for s in names}

    assigned: dict[str, str] = {}
    per_tag: dict[str, dict[str, int]] = defaultdict(lambda: {s: 0 for s in names})

    # Deterministic tie-breaking without a RNG: a stable hash of the repo name orders
    # otherwise-equivalent candidates the same way on every machine and every rerun.
    def order_key(repo: str) -> str:
        return hashlib.sha256(f"{SEED}:{repo}".encode()).hexdigest()

    for rank, (tag, repos) in enumerate(ranked):
        pending = sorted((r for r in repos if r not in assigned), key=order_key)
        if not pending:
            continue
        n_tag = len(repos)
        for repo in pending:
            counts = {s: len(
                [r for r, sp in assigned.items() if sp == s]
            ) for s in names}

            def deficit(s: str) -> tuple[float, float, str]:
                want_tag = share[s] * n_tag
                # Rare tags (rank inside the stratified head) weight the per-tag
                # deficit; past that only overall balance matters.
                tag_gap = want_tag - per_tag[tag][s] if rank < STRATIFY_TOP_N else 0.0
                size_gap = TARGET[s] - counts[s]
                return (-tag_gap, -size_gap, s)

            # A tag with fewer than 3 positive repos cannot be spread; synthesis needs
            # the material more than measurement does, so TRAIN-SYN takes it.
            if n_tag < 3 and counts["train_syn"] < TARGET["train_syn"]:
                pick = "train_syn"
            else:
                pick = min(
                    (s for s in names if counts[s] < TARGET[s]) or names, key=deficit
                )

            assigned[repo] = pick
            for t in repo_tags[repo]:
                per_tag[t][pick] += 1

    out: dict[str, list[str]] = {s: [] for s in names}
    for repo, split in assigned.items():
        out[split].append(repo)
    for s in out:
        out[s].sort()
    return out


def main() -> int:
    csv_path = DATA / "train.csv"
    repo_tags = load_repo_tags(csv_path)
    splits = allocate(repo_tags)

    tag_counts: dict[str, int] = defaultdict(int)
    for tags in repo_tags.values():
        for t in tags:
            tag_counts[t] += 1
    ranked = sorted(tag_counts.items(), key=lambda kv: (-kv[1], kv[0]))

    per_tag: dict[str, dict[str, int]] = {}
    uncovered: dict[str, list[str]] = defaultdict(list)
    for tag, _ in ranked:
        row = {}
        for s, repos in splits.items():
            row[s] = sum(1 for r in repos if tag in repo_tags[r])
            if row[s] == 0:
                uncovered[s].append(tag)
        per_tag[tag] = row

    payload = {
        "seed": SEED,
        "source_csv": str(csv_path),
        "source_sha256": hashlib.sha256(csv_path.read_bytes()).hexdigest(),
        "n_repos": len(repo_tags),
        "sizes": {s: len(v) for s, v in splits.items()},
        **{s: v for s, v in splits.items()},
        "per_tag_counts": per_tag,
        "uncovered": dict(uncovered),
    }
    body = json.dumps(payload, indent=2, sort_keys=True)
    payload["splits_sha256"] = hashlib.sha256(body.encode()).hexdigest()
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True))

    print(f"{len(repo_tags)} repositories -> " + " / ".join(
        f"{s} {len(v)}" for s, v in splits.items()))
    print(f"splits_sha256 {payload['splits_sha256'][:16]}...\n")
    print(f"{'tag':<22}{'repos':>6}{'TRAIN-SYN':>11}{'DEV':>5}{'TEST':>6}")
    print("-" * 50)
    for tag, n in ranked:
        r = per_tag[tag]
        flag = "" if all(r[s] for s in TARGET) else "   <- gap"
        marker = flag if n >= 3 else ""
        print(f"{tag:<22}{n:>6}{r['train_syn']:>11}{r['dev']:>5}{r['test']:>6}{marker}")
    print("-" * 50)
    head = [t for t, _ in ranked[:STRATIFY_TOP_N]]
    complete = [t for t in head if all(per_tag[t][s] for s in TARGET)]
    print(f"top-{STRATIFY_TOP_N} tags present in all three splits: "
          f"{len(complete)}/{STRATIFY_TOP_N}")
    for s in TARGET:
        print(f"  {s:<10} missing {len(uncovered.get(s, []))} tags entirely")
    print(f"\nWrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

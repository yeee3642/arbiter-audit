#!/usr/bin/env python3
"""Prove the split held. Declaring one is not the same as enforcing it.

Detector synthesis reads labelled findings and writes them into prompts. Any repository
it touches is permanently unusable for measurement, because a detector induced from a
bug is guaranteed to find that bug again. The same applies more subtly to calibration:
tuning a threshold on a repository means the threshold has seen its labels.

So the split has three roles and three rules:

  TRAIN-SYN (32)  synthesis, retrieval knowledge base, routing IDF corpus
  DEV       (10)  threshold and prior calibration, every prompt iteration
  TEST      (12)  read once, at the end, after everything is frozen

  rule 1  no synthesised detector may cite evidence from DEV or TEST
  rule 2  no calibration artefact may reference TEST
  rule 3  TEST appears in at most one scan run

This checks the artefacts on disk rather than trusting that the code was written
correctly. Synthesised detectors record which repositories their examples came from;
run manifests record which repositories were scanned. Both are compared against the
frozen split, and the split file itself is re-hashed to catch edits after the freeze.

Overfitting has a second face this also reports: a detector induced from a single
repository will encode that repository's naming rather than the vulnerability class.
`hints.py` enforces a >=2-repository rule for tags with enough positives; tags below
that threshold are listed here so the writeup can mark them rather than quietly
claiming them.

Run:  python scripts/leakage_audit.py
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
PKG = Path(__file__).resolve().parents[1]
SPLITS = DATA / "splits.json"

REPO_RE = re.compile(r"\b[0-9a-f]{12}\b")


def load_splits() -> tuple[dict[str, set[str]], dict]:
    payload = json.loads(SPLITS.read_text())
    splits = {k: set(payload[k]) for k in ("train_syn", "dev", "test")}
    return splits, payload


def verify_freeze(payload: dict) -> bool:
    """Re-derive the recorded hash so a post-freeze edit cannot pass silently."""
    recorded = payload.get("splits_sha256")
    if not recorded:
        return False
    body = {k: v for k, v in payload.items() if k != "splits_sha256"}
    recomputed = hashlib.sha256(
        json.dumps(body, indent=2, sort_keys=True).encode()
    ).hexdigest()
    return recomputed == recorded


def scan_text_for_repos(text: str) -> set[str]:
    """Repository hashes are 12 hex characters, which is specific enough to grep for."""
    return set(REPO_RE.findall(text))


def audit_detectors(splits: dict[str, set[str]]) -> list[dict]:
    """Every synthesised detector, and which splits its evidence came from."""
    out = []
    synth_dir = PKG / "detectors_synth"
    if not synth_dir.is_dir():
        return out
    for md in sorted(synth_dir.glob("*.md")):
        cited = scan_text_for_repos(md.read_text(errors="ignore"))
        out.append({
            "detector": md.stem,
            "cited_repos": len(cited),
            "from_train_syn": len(cited & splits["train_syn"]),
            "from_dev": sorted(cited & splits["dev"]),
            "from_test": sorted(cited & splits["test"]),
        })
    return out


def audit_runs(splits: dict[str, set[str]]) -> list[dict]:
    """Which split each recorded run touched, from its manifest and results."""
    out = []
    runs_dir = PKG / "runs"
    if not runs_dir.is_dir():
        return out
    for run in sorted(p for p in runs_dir.iterdir() if p.is_dir()):
        seen: set[str] = set()
        for name in ("manifest.json", "tasks.jsonl", "results.jsonl", "findings.json"):
            f = run / name
            if f.exists():
                seen |= scan_text_for_repos(f.read_text(errors="ignore"))
        if not seen:
            continue
        out.append({
            "run": run.name,
            "train_syn": len(seen & splits["train_syn"]),
            "dev": len(seen & splits["dev"]),
            "test": sorted(seen & splits["test"]),
        })
    return out


def audit_single_repo_tags(splits: dict[str, set[str]]) -> list[tuple[str, int]]:
    """Tags whose synthesis material comes from too few repositories to generalise."""
    import pandas as pd
    from bastet_cc.evaluate import normalize_tag, parse_tags

    df = pd.read_csv(DATA / "train.csv")
    per_tag: dict[str, set[str]] = {}
    for repo, raw in zip(df["repo_path"], df["tag"]):
        key = str(repo).strip()
        if key not in splits["train_syn"]:
            continue
        for t in parse_tags(raw):
            per_tag.setdefault(normalize_tag(t), set()).add(key)
    return sorted(
        ((t, len(r)) for t, r in per_tag.items() if len(r) < 2),
        key=lambda kv: kv[0],
    )


def main() -> int:
    splits, payload = load_splits()

    print("=" * 74)
    print("SPLIT")
    print("=" * 74)
    for name in ("train_syn", "dev", "test"):
        print(f"  {name:<10}{len(splits[name]):>4} repositories")
    overlap = (
        (splits["train_syn"] & splits["dev"])
        | (splits["train_syn"] & splits["test"])
        | (splits["dev"] & splits["test"])
    )
    frozen = verify_freeze(payload)
    print(f"  pairwise overlap        : {len(overlap)}  {'OK' if not overlap else 'LEAK'}")
    print(f"  splits_sha256 verifies  : {'yes' if frozen else 'NO -- file edited since freeze'}")

    violations = 0

    print()
    print("=" * 74)
    print("RULE 1 -- synthesised detectors cite only TRAIN-SYN evidence")
    print("=" * 74)
    dets = audit_detectors(splits)
    if not dets:
        print("  no synthesised detectors on disk yet")
    else:
        bad = [d for d in dets if d["from_dev"] or d["from_test"]]
        print(f"  {len(dets)} detectors, "
              f"{sum(d['from_train_syn'] for d in dets)} TRAIN-SYN citations total")
        if bad:
            violations += len(bad)
            for d in bad:
                print(f"  LEAK {d['detector']}: dev={d['from_dev']} test={d['from_test']}")
        else:
            print("  no detector cites DEV or TEST  OK")

    print()
    print("=" * 74)
    print("RULE 2/3 -- which split each run touched")
    print("=" * 74)
    runs = audit_runs(splits)
    if not runs:
        print("  no runs with recorded repositories yet")
    else:
        print(f"  {'run':<24}{'TRAIN-SYN':>10}{'DEV':>6}{'TEST':>6}")
        test_runs = []
        for r in runs:
            n_test = len(r["test"])
            flag = "  <- TEST" if n_test else ""
            print(f"  {r['run']:<24}{r['train_syn']:>10}{r['dev']:>6}{n_test:>6}{flag}")
            if n_test:
                test_runs.append(r["run"])
        if len(test_runs) > 1:
            violations += 1
            print(f"\n  VIOLATION: TEST appears in {len(test_runs)} runs: {test_runs}")
            print("  The freeze protocol allows exactly one.")
        elif test_runs:
            print(f"\n  TEST read once, by {test_runs[0]}  OK")
        else:
            print("\n  TEST unread  OK")

    print()
    print("=" * 74)
    print("OVERFITTING -- tags with too little material to generalise")
    print("=" * 74)
    thin = audit_single_repo_tags(splits)
    if thin:
        print(f"  {len(thin)} tags have <2 positive repositories in TRAIN-SYN.")
        print("  A detector induced from one repository encodes that repository's naming,")
        print("  not the vulnerability class. These must be reported as such.")
        print("  " + ", ".join(f"{t}({n})" for t, n in thin))
    else:
        print("  every tag has >=2 positive repositories in TRAIN-SYN")

    print()
    print("=" * 74)
    status = "PASS" if violations == 0 and frozen and not overlap else "FAIL"
    print(f"LEAKAGE AUDIT: {status}   ({violations} violation(s))")
    print("=" * 74)

    (PKG / "runs" / "leakage_audit.json").write_text(json.dumps({
        "status": status,
        "violations": violations,
        "splits_frozen": frozen,
        "pairwise_overlap": sorted(overlap),
        "detectors": dets,
        "runs": runs,
        "thin_tags": [{"tag": t, "n_repos": n} for t, n in thin],
    }, indent=2))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())

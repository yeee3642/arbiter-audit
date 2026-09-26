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


def _provenance_repos(md_text: str) -> tuple[set[str], str]:
    """Repositories a synthesised detector was induced from.

    Three sources, in order of directness:

      1. `synth_provenance.train_findings` in the front matter -- finding row ids,
         mapped back to repositories through train.csv. This is the real answer:
         it is what S2 read.
      2. The S2/LORO artefacts under runs/synth/, whose filenames carry the
         held-out repo hash (`<tag>__loro_<repo>.json`).
      3. A hash grep over the prompt body.

    (3) alone was the original implementation, and it is **vacuous**: the
    generator never writes repo hashes into the prompt, so the grep matched
    nothing in all 23 detectors and the rule passed by construction. A check that
    cannot fail is not a check, and this one was reporting PASS on the single
    most leak-prone stage in the pipeline. Returns the source actually used so
    the report can say which.
    """
    import re as _re

    m = _re.search(r"^synth_provenance:\s*(\{.*\})\s*$", md_text, _re.M)
    if m:
        try:
            prov = json.loads(m.group(1))
            ids = [str(x) for x in (prov.get("train_findings") or [])]
            if ids:
                return set(ids), "front_matter_finding_ids"
            # S2b induces from the tag definition alone, for tags with no
            # TRAIN-SYN positives at all. No labelled finding was read, so this
            # is not a leak -- but it is not a clean bill of health either: the
            # detector has no training material and, for these tags, its only
            # positive repository lives in TEST. Reported as its own category so
            # the coverage claim can be honest about it.
            if prov.get("mode") == "s2b":
                return set(), "no_training_material"
        except json.JSONDecodeError:
            pass
    return scan_text_for_repos(md_text), "hash_grep_fallback"


def _finding_id_to_repo() -> dict[str, str]:
    """train.csv row id -> repo hash, for resolving front-matter provenance.

    Upstream's `Property` column is the finding id the synthesis pipeline
    records. Absent that column the mapping degrades to positional index, which
    is what `train_findings` holds when the pipeline enumerated rows.
    """
    import pandas as pd

    df = pd.read_csv(DATA / "train.csv")
    id_col = "Property" if "Property" in df.columns else None
    out: dict[str, str] = {}
    for i, (_, row) in enumerate(df.iterrows()):
        repo = str(row["repo_path"]).strip()
        out[str(i)] = repo
        if id_col is not None:
            try:
                out[str(int(row[id_col]))] = repo
            except (TypeError, ValueError):
                pass
    return out


def audit_detectors(splits: dict[str, set[str]]) -> list[dict]:
    """Every synthesised detector, and which splits its evidence came from."""
    out = []
    synth_dir = PKG / "detectors_synth"
    if not synth_dir.is_dir():
        return out

    try:
        id2repo = _finding_id_to_repo()
    except (OSError, KeyError):
        id2repo = {}

    for md in sorted(synth_dir.glob("*.md")):
        raw, source = _provenance_repos(md.read_text(errors="ignore"))
        if source == "front_matter_finding_ids":
            cited = {id2repo[i] for i in raw if i in id2repo}
            unresolved = sorted(i for i in raw if i not in id2repo)
        else:
            cited, unresolved = raw, []
        out.append({
            "detector": md.stem,
            "provenance_source": source,
            "cited_repos": len(cited),
            "unresolved_ids": unresolved,
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


def audit_single_repo_tags(splits: dict[str, set[str]]) -> list[tuple[str, int]] | None:
    """Tags whose synthesis material comes from too few repositories to generalise.

    Returns None when train.csv is absent. The corpus is deliberately not in the
    repository, so this section is the one part of the audit a fresh clone cannot
    run -- and it must degrade rather than take the leakage rules down with it,
    since those are the part that actually gates the protocol.
    """
    import pandas as pd
    from bastet_cc.evaluate import normalize_tag, parse_tags

    if not (DATA / "train.csv").exists():
        return None
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
        # S2b detectors read no labelled finding, so they cannot leak. They are
        # reported separately because they also cannot be *validated*: no
        # training material means no LORO fold, and for these tags the only
        # positive repository is in TEST.
        no_material = [d for d in dets
                       if d["provenance_source"] == "no_training_material"]
        # Anything else that fails to resolve is genuinely unverifiable. The
        # original rule counted exactly this case as clean, which is how a
        # vacuous grep reported PASS on 23 detectors it never inspected.
        blind = [d for d in dets
                 if d["provenance_source"] not in
                 ("front_matter_finding_ids", "no_training_material")]
        # A detector that declares provenance we could not resolve is unverified,
        # not clean. Without train.csv every finding id is unresolvable, and
        # printing OK there would repeat the exact failure this rule was rewritten
        # to remove -- a check reporting PASS on evidence it never read.
        unresolved = [d for d in dets
                      if d["provenance_source"] == "front_matter_finding_ids"
                      and d["cited_repos"] == 0 and d["unresolved_ids"]]

        print(f"  {len(dets)} detectors, "
              f"{sum(d['from_train_syn'] for d in dets)} TRAIN-SYN citations total")
        if bad:
            violations += len(bad)
            for d in bad:
                print(f"  LEAK {d['detector']}: dev={d['from_dev']} test={d['from_test']}")
        if blind:
            violations += len(blind)
            print(f"  UNVERIFIABLE: {len(blind)} detector(s) expose no resolvable"
                  f" provenance, so this rule cannot clear them:")
            for d in blind[:5]:
                print(f"    {d['detector']}  (source={d['provenance_source']})")
        if no_material:
            print(f"  NO TRAINING MATERIAL: {len(no_material)} detector(s) induced"
                  f" from the tag definition only (S2b) -- not a leak, but they")
            print(f"  cannot be validated before TEST and should be excluded from"
                  f" any coverage figure that implies evidence:")
            for d in no_material:
                print(f"    {d['detector']}")
        if unresolved:
            missing_csv = not (DATA / "train.csv").exists()
            why = ("data/train.csv absent, so finding ids cannot be mapped to "
                   "repositories" if missing_csv else
                   "finding ids are not present in train.csv")
            print(f"  UNRESOLVED: {len(unresolved)} detector(s) declare provenance "
                  f"that could not be checked")
            print(f"    ({why})")
            print(f"    This rule is INCONCLUSIVE for them -- not a pass. Re-run with"
                  f" the corpus present before citing it.")
        if not bad and not blind and not unresolved:
            n_ok = len(dets) - len(no_material)
            print(f"  {n_ok} detector(s) resolve to TRAIN-SYN evidence only  OK")

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
    if thin is None:
        print("  data/train.csv not present -- section skipped (the corpus is not")
        print("  redistributed; see README). The leakage rules above do not need it.")
        thin = []
    elif thin:
        print(f"  {len(thin)} tags have <2 positive repositories in TRAIN-SYN.")
        print("  A detector induced from one repository encodes that repository's naming,")
        print("  not the vulnerability class. These must be reported as such.")
        print("  " + ", ".join(f"{t}({n})" for t, n in thin))
    else:
        print("  every tag has >=2 positive repositories in TRAIN-SYN")

    print()
    print("=" * 74)
    inconclusive = bool(dets) and any(
        d["provenance_source"] == "front_matter_finding_ids"
        and d["cited_repos"] == 0 and d["unresolved_ids"] for d in dets)
    if violations or not frozen or overlap:
        status = "FAIL"
    elif inconclusive:
        # Distinct from PASS on purpose. The rules that ran are clean, but Rule 1
        # could not read the evidence it exists to check, and a green light there
        # is what the previous vacuous implementation produced.
        status = "INCONCLUSIVE"
    else:
        status = "PASS"
    print(f"LEAKAGE AUDIT: {status}   ({violations} violation(s))")
    if status == "INCONCLUSIVE":
        print("Rule 1 could not resolve detector provenance; rerun with data/train.csv.")
    print("=" * 74)

    (PKG / "runs" / "leakage_audit.json").write_text(json.dumps({
        "status": status,
        "violations": violations,
        "splits_frozen": frozen,
        "pairwise_overlap": sorted(overlap),
        "detectors": dets,
        "runs": runs,
        "thin_tags": [{"tag": t, "n_repos": n} for t, n in thin],
        "thin_tags_available": bool(thin) or (DATA / "train.csv").exists(),
        "inconclusive": inconclusive,
    }, indent=2))
    return 0 if status in ("PASS", "INCONCLUSIVE") else 1


if __name__ == "__main__":
    sys.exit(main())

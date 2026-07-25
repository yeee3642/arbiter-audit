#!/usr/bin/env python3
"""E7 -- how much of this corpus has the model already read?

Every repository here is a public Code4rena contest, and the findings we score against
are published audit reports. A model trained on the open web plausibly memorised some
of them, which would inflate any absolute score we report.

The probe withholds the code. It hands the model only what identifies the project --
contract names and the README -- and asks which vulnerabilities the audit found. With
no code to reason from, agreement with ground truth can only come from prior knowledge
of this specific contest.

Raw agreement would overstate that badly. Answering "DoS, Input Validation, Access
Control" to every project scores well on this corpus because those tags dominate it,
and that reflects the tag distribution rather than any memory of the project. So the
comparison is against a frequency-prior baseline that always predicts the k most common
tags. The gap between the two is the part attributable to knowing *this* project.

Runs on DEV, not TEST. The measurement is a property of the corpus, so DEV answers it
just as well, and the freeze protocol keeps TEST unread until D5.

Run:  python scripts/e7_memorization_probe.py
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import re
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bastet_cc.evaluate import normalize_tag, parse_tags  # noqa: E402
from bastet_cc.llm import LLMClient  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
OUT = Path(__file__).resolve().parents[1] / "runs" / "e7"
MODEL = "ais3/nemotron-3-ultra-550b"
BASE_URL = "https://llm-api.zoolab.org/v1"
API_KEY = os.environ.get("AIS3_API_KEY") or sys.exit(
    "set AIS3_API_KEY (the AIS3 LLM gateway token); it is deliberately not in the repo"
)

PROBE_SCHEMA = {
    "type": "object",
    "properties": {
        "recognised": {"type": "boolean"},
        "project_guess": {"type": "string"},
        "tags": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["recognised", "project_guess", "tags"],
}
TOP_K = 6                      # tags requested from the model, and used by the baseline
README_CHARS = 4000
MAX_CONTRACTS = 60

SYSTEM = (
    "You are a smart contract security researcher with broad knowledge of public audit "
    "contests. Answer only with JSON."
)

TEMPLATE = """Below is the identifying information for a Solidity project that was
audited in a public contest. You are NOT given the source code.

Project files and contract names:
{contracts}

README excerpt:
{readme}

From your prior knowledge of public audit reports for this specific project, list the
vulnerability categories the auditors actually reported. If you do not recognise the
project, say so rather than guessing from the tag names.

Reply with JSON only:
{{"recognised": true|false,
  "project_guess": "name or empty string",
  "tags": ["at most {k} category names"]}}

Use these category names exactly where they apply: {taxonomy}
"""


def repo_identity(repo_dir: Path) -> tuple[str, str]:
    """Contract names and README text -- identity without implementation."""
    names: list[str] = []
    for sol in sorted(repo_dir.rglob("*.sol")):
        rel = str(sol.relative_to(repo_dir))
        if re.search(r"(^|/)(node_modules|lib|out|artifacts|cache)(/|$)", rel, re.I):
            continue
        names.append(rel)
        if len(names) >= MAX_CONTRACTS:
            break

    readme = ""
    for cand in ("README.md", "readme.md", "README-sponsor.md"):
        p = repo_dir / cand
        if p.exists():
            readme = p.read_text(errors="ignore")[:README_CHARS]
            break
    return "\n".join(names), readme


def jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b) if (a | b) else 0.0


async def main() -> int:
    splits = json.loads((DATA / "splits.json").read_text())
    dev = splits["dev"]

    df = pd.read_csv(DATA / "train.csv")
    truth: dict[str, set[str]] = {}
    for repo, raw in zip(df["repo_path"], df["tag"]):
        truth.setdefault(str(repo).strip(), set()).update(
            normalize_tag(t) for t in parse_tags(raw)
        )

    # Frequency prior computed on TRAIN-SYN only: using DEV's own distribution would
    # hand the baseline information the model never had.
    train_syn = set(splits["train_syn"])
    prior = Counter()
    for repo, tags in truth.items():
        if repo in train_syn:
            prior.update(tags)
    baseline_tags = {t for t, _ in prior.most_common(TOP_K)}
    taxonomy = sorted({t for tags in truth.values() for t in tags})

    client = LLMClient(base_url=BASE_URL, api_key=API_KEY, model=MODEL)
    rows = []
    for repo in dev:
        repo_dir = DATA / "ex" / "train" / repo
        if not repo_dir.is_dir():
            print(f"  skip {repo}: not extracted")
            continue
        contracts, readme = repo_identity(repo_dir)
        prompt = TEMPLATE.format(
            contracts=contracts or "(none found)",
            readme=readme or "(no README)",
            k=TOP_K,
            taxonomy=", ".join(taxonomy),
        )

        res = await client.complete(
            system=SYSTEM, user=prompt, schema=PROBE_SCHEMA, max_tokens=600
        )
        obj = res.parsed if isinstance(res.parsed, dict) else {}
        if not obj and res.text:
            try:
                obj = json.loads(res.text)
            except Exception:
                obj = {}
        if not isinstance(obj, dict):
            obj = {}

        predicted = {normalize_tag(t) for t in (obj.get("tags") or []) if isinstance(t, str)}
        predicted &= set(taxonomy)
        actual = truth.get(repo, set())

        rows.append({
            "repo": repo,
            "recognised": bool(obj.get("recognised")),
            "project_guess": str(obj.get("project_guess") or "")[:60],
            "n_true": len(actual),
            "model_jaccard": jaccard(predicted, actual),
            "model_recall": len(predicted & actual) / len(actual) if actual else None,
            "baseline_jaccard": jaccard(baseline_tags, actual),
            "baseline_recall": (
                len(baseline_tags & actual) / len(actual) if actual else None
            ),
            "predicted": ", ".join(sorted(predicted)),
        })
        print(f"  {repo}  recognised={rows[-1]['recognised']}  "
              f"J_model={rows[-1]['model_jaccard']:.3f}  "
              f"J_prior={rows[-1]['baseline_jaccard']:.3f}  "
              f"guess={rows[-1]['project_guess'][:32]}")

    if not rows:
        print("no repositories evaluated")
        return 1

    out = pd.DataFrame(rows)
    OUT.mkdir(parents=True, exist_ok=True)
    out.to_csv(OUT / "e7_memorization.csv", index=False)

    mj = out["model_jaccard"].mean()
    bj = out["baseline_jaccard"].mean()
    mr = out["model_recall"].dropna().mean()
    br = out["baseline_recall"].dropna().mean()
    n_rec = int(out["recognised"].sum())

    # Paired bootstrap over repositories: the quantity of interest is the per-repo gap.
    rng = random.Random(20260725)
    diffs = out["model_jaccard"] - out["baseline_jaccard"]
    boots = []
    for _ in range(2000):
        s = [diffs.iloc[rng.randrange(len(diffs))] for _ in range(len(diffs))]
        boots.append(sum(s) / len(s))
    boots.sort()
    lo, hi = boots[int(0.025 * len(boots))], boots[int(0.975 * len(boots))]

    print()
    print(f"{'':<26}{'Jaccard':>9}{'recall':>9}")
    print(f"{'model, code withheld':<26}{mj:>9.3f}{mr:>9.3f}")
    print(f"{'frequency prior (top-6)':<26}{bj:>9.3f}{br:>9.3f}")
    print(f"{'gap':<26}{mj - bj:>+9.3f}")
    print(f"\npaired bootstrap 95% CI on the gap: [{lo:+.3f}, {hi:+.3f}]")
    print(f"claimed to recognise the project: {n_rec}/{len(out)} repositories")
    print()
    if lo > 0:
        print("The gap excludes zero: the model carries project-specific prior knowledge.")
        print("Absolute scores must be reported as possibly inflated; the paired")
        print("architecture comparison is unaffected, since both arms share the model.")
    else:
        print("The gap does not exclude zero. Agreement is explained by the tag")
        print("distribution alone -- no measurable memorisation of these projects.")

    (OUT / "e7_summary.json").write_text(json.dumps({
        "model": MODEL,
        "split": "dev",
        "n_repos": len(out),
        "model_jaccard": mj,
        "baseline_jaccard": bj,
        "gap": mj - bj,
        "gap_ci95": [lo, hi],
        "n_recognised": n_rec,
        "baseline_tags": sorted(baseline_tags),
    }, indent=2))
    print(f"\nWrote {OUT / 'e7_memorization.csv'}")
    await client.aclose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

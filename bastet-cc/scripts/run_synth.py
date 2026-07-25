"""Driver for detector synthesis (DESIGN §2.3): S1 -> S2 -> S3 -> S4 -> assemble.

Stages are separately invocable and every stage caches its artifacts under
runs/synth/, so a crash mid-S4 costs only the folds that had not finished. Nothing
here reads a label outside TRAIN-SYN: `train_syn_frames()` is the single entry point
for ground truth, and S3's document frequencies are computed over repo *code* only.

  python scripts/run_synth.py s1 [--limit N]
  python scripts/run_synth.py s2 [--tags "A,B"]
  python scripts/run_synth.py s4 [--tags "A,B"]
  python scripts/run_synth.py assemble
  python scripts/run_synth.py report
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bastet_cc.llm import LLMClient
from bastet_cc.synth import (DATA_DIR, DETECTORS_SYNTH_DIR, PKG_ROOT, TRAIN_EX_DIR,
                             covered_tags, index_train_repos, load_splits,
                             missing_tags, train_syn_frames)
from bastet_cc.synth.assemble import assemble_all, detector_id
from bastet_cc.synth.gate import (localized_ident_sets, localized_repos, run_s4,
                                  tag_positive_repos)
from bastet_cc.synth.hints import build_file_sets, required_hints_for, validate_hints
from bastet_cc.synth.induce import (induce_tag, load_induction, parse_tag_definitions,
                                    save_induction)
from bastet_cc.synth.localize import localization_rates, run_s1

BASE_URL = "https://llm-api.zoolab.org/v1"
API_KEY = os.environ.get("AIS3_API_KEY") or sys.exit(
    "set AIS3_API_KEY (the AIS3 LLM gateway token); it is deliberately not in the repo"
)
MODEL = "ais3/nemotron-3-ultra-550b"

RUN_DIR = PKG_ROOT / "runs" / "synth"
S1_PATH = RUN_DIR / "s1_localize.json"
S2_DIR = RUN_DIR / "s2"
S3_PATH = RUN_DIR / "s3_hints.json"
S4_PATH = RUN_DIR / "s4_gate.json"
GATE_WORKDIR = RUN_DIR / "gate_variants"
LOG_PATH = RUN_DIR / "llm_calls.jsonl"


def client(concurrency: int = 32) -> LLMClient:
    return LLMClient(BASE_URL, API_KEY, MODEL, max_concurrency=concurrency,
                     log_path=LOG_PATH)


def all_train_repos() -> list[str]:
    """Every extracted train repo: S3's vocabulary is code-wide (DESIGN §2.3 S3.1),
    only the positive-repo labels come from TRAIN-SYN."""
    return sorted(p.name for p in TRAIN_EX_DIR.iterdir() if p.is_dir())


def synth_tags(splits: dict) -> list[str]:
    return missing_tags(splits)


def load_s1() -> list[dict]:
    return json.loads(S1_PATH.read_text())


async def stage_s1(args) -> None:
    raw, _exp, _sp = train_syn_frames()
    if args.limit:
        raw = raw.head(args.limit)
    indexes = index_train_repos(sorted(set(raw["repo_path"])))
    cl = client(args.concurrency)
    try:
        records = await run_s1(raw, indexes, cl, S1_PATH)
    finally:
        await cl.aclose()
    n_loc = sum(r["localized"] for r in records)
    print(f"S1: {len(records)} findings, localized {n_loc} "
          f"({n_loc / max(1, len(records)):.1%}), errors "
          f"{sum(1 for r in records if r['error'])}")
    print(json.dumps(localization_rates(records), indent=1)[:2000])


async def stage_s2(args) -> None:
    splits = load_splits()
    records = load_s1()
    tagdefs = parse_tag_definitions()
    tags = args.tags.split(",") if args.tags else synth_tags(splits)
    cl = client(args.concurrency)
    try:
        todo = [t for t in tags if args.force or load_induction(t, S2_DIR) is None]
        results = await asyncio.gather(*(
            induce_tag(t, tagdefs[t], records, cl) for t in todo))
        for rec in results:
            save_induction(rec, S2_DIR)
    finally:
        await cl.aclose()
    for t in tags:
        rec = load_induction(t, S2_DIR)
        d = rec["detector"]
        print(f"{t:20s} mode={rec['mode']:4s} fallback={rec['fallback']} "
              f"checks={len(d['checks'])} hints={len(d['routing_hint_candidates'])} "
              f"triples={len(rec['triples_used'])} err={rec['error']}")


def stage_s3(args) -> None:
    splits = load_splits()
    records = load_s1()
    tags = args.tags.split(",") if args.tags else synth_tags(splits)
    indexes = index_train_repos(all_train_repos())
    file_sets = build_file_sets(indexes)
    out: dict[str, dict] = {}
    if S3_PATH.exists() and not args.force:
        out = json.loads(S3_PATH.read_text())
    for t in tags:
        rec = load_induction(t, S2_DIR)
        if rec is None:
            print(f"{t}: no S2 artifact, skipped")
            continue
        pos = tag_positive_repos(records, t)
        res = validate_hints(t, rec["detector"]["routing_hint_candidates"], file_sets,
                             pos, localized_ident_sets(records, t),
                             localized_repos(records, t))
        res["required_hints"] = required_hints_for(t, file_sets, pos)
        out[t] = res
        print(f"{t:20s} cand={res['n_candidates']:3d} kept={len(res['kept']):2d} "
              f"cov={res['coverage']:.2f} fb={res['fallback_used']} "
              f"req={res['required_hints']} {res['kept']}")
    S3_PATH.parent.mkdir(parents=True, exist_ok=True)
    S3_PATH.write_text(json.dumps(out, indent=1))


async def stage_s4(args) -> None:
    splits = load_splits()
    records = load_s1()
    tagdefs = parse_tag_definitions()
    tags = args.tags.split(",") if args.tags else synth_tags(splits)
    indexes = index_train_repos(all_train_repos())
    file_sets = build_file_sets(indexes)
    cl = client(args.concurrency)
    try:
        res = await run_s4(tags, tagdefs, records, indexes, file_sets,
                           splits["train_syn"], cl, GATE_WORKDIR, S2_DIR, S4_PATH)
    finally:
        await cl.aclose()
    for t in tags:
        r = res.get(t)
        if r is None:
            continue
        print(f"{t:20s} loro={r.get('loro')} folds={len(r['folds'])} "
              f"hit={r['hit_mean']} fp={r['fp_mean']} passed={r['passed']} "
              f"repaired={r['repaired']} calls={r.get('n_calls')}")


def stage_assemble(args) -> None:
    splits = load_splits()
    records = load_s1()
    hints = json.loads(S3_PATH.read_text())
    gates = json.loads(S4_PATH.read_text()) if S4_PATH.exists() else {}
    tags = args.tags.split(",") if args.tags else synth_tags(splits)

    final: list[dict] = []
    for t in tags:
        s2 = load_induction(t, S2_DIR)
        if s2 is None:
            print(f"{t}: no S2 artifact, skipped")
            continue
        h = hints.get(t, {"kept": [], "required_hints": [], "coverage": 0.0,
                          "single_repo_hints": True, "fallback_used": True,
                          "rejected": {}, "n_candidates": 0})
        g = gates.get(t, {})
        rate = _localization_rate(records, t)
        # Gate policy (DESIGN §2.3 S4.6): anything not demonstrably passing LORO
        # ships gated. S2b output and hint-starved detectors are gated by
        # construction, since neither had evidence to earn a pass.
        gated = bool(
            g.get("passed") is not True
            or s2["mode"] == "s2b" or s2["fallback"]
            or len(h["kept"]) < 2)
        final.append({
            "tag": t,
            "detector": s2["detector"],
            "routing_hints": h["kept"],
            "required_hints": h.get("required_hints", []),
            "gated": gated,
            "provenance": {
                "train_findings": s2["triples_used"],
                "localization_rate": rate,
                "mode": s2["mode"],
                "hint_candidates": h["n_candidates"],
                "hints_rejected": len(h.get("rejected", {})),
                "hint_coverage": h["coverage"],
                "single_repo_hints": h["single_repo_hints"],
                "hint_fallback": h["fallback_used"],
                "loro": ({"hit": g.get("hit_mean"), "fp": g.get("fp_mean"),
                          "folds": len(g.get("folds", [])),
                          "repaired": g.get("repaired", False)}
                         if g.get("folds") else None),
            },
        })
    index = assemble_all(final, DETECTORS_SYNTH_DIR)
    n_gated = sum(1 for d in index if d["gated"])
    print(f"assembled {len(index)} detectors into {DETECTORS_SYNTH_DIR} "
          f"({n_gated} gated, {len(index) - n_gated} passing)")


def _localization_rate(records: list[dict], tag: str) -> float:
    rows = [r for r in records if tag in r["tags"]]
    if not rows:
        return 0.0
    return round(sum(r["localized"] for r in rows) / len(rows), 3)


def stage_report(args) -> None:
    import pandas as pd

    splits = load_splits()
    records = load_s1()
    tags = synth_tags(splits)
    covered = covered_tags()
    synth_index = json.loads((DETECTORS_SYNTH_DIR / "index.json").read_text())
    synth_covered = {t for d in synth_index for t in d["tags"]}

    # Corpus-wide reach comes from splits.json's frozen per_tag_counts, not from
    # re-reading rows: the counts are split metadata, and this keeps the report
    # runnable without ever opening a label file.
    counts = splits["per_tag_counts"]
    total = sum(sum(v.values()) for v in counts.values())
    reach = lambda tags: sum(sum(v.values()) for t, v in counts.items() if t in tags)
    before, after = reach(covered), reach(covered | synth_covered)
    print(f"(finding,tag) pairs in corpus: {total}  "
          f"reachable before {before} ({before/total:.1%})  "
          f"after {after} ({after/total:.1%})")
    print(f"tags with a detector: {len(covered)} -> {len(covered | synth_covered)} "
          f"of {len(counts)} corpus tags")
    syn_total = sum(v.get("train_syn", 0) for v in counts.values())
    syn_before = sum(v.get("train_syn", 0) for t, v in counts.items() if t in covered)
    syn_after = sum(v.get("train_syn", 0) for t, v in counts.items()
                    if t in covered | synth_covered)
    print(f"TRAIN-SYN only: {syn_total} pairs, before {syn_before} "
          f"({syn_before/syn_total:.1%}), after {syn_after} ({syn_after/syn_total:.1%})")

    s1_repo_tags = {(r["repo"], t) for r in records for t in r["tags"]}
    rb = sum(1 for _, t in s1_repo_tags if t in covered)
    ra = sum(1 for _, t in s1_repo_tags if t in covered | synth_covered)
    print(f"TRAIN-SYN (repo,tag) positives: {len(s1_repo_tags)}  "
          f"before {rb} ({rb/len(s1_repo_tags):.1%})  "
          f"after {ra} ({ra/len(s1_repo_tags):.1%})")

    hints = json.loads(S3_PATH.read_text())
    gates = json.loads(S4_PATH.read_text()) if S4_PATH.exists() else {}
    rows = []
    for t in tags:
        s2 = load_induction(t, S2_DIR) or {}
        h = hints.get(t, {})
        g = gates.get(t, {})
        rows.append({
            "tag": t,
            "n_syn_findings": sum(1 for r in records if t in r["tags"]),
            "loc_rate": _localization_rate(records, t),
            "mode": s2.get("mode"),
            "cand": h.get("n_candidates"),
            "kept": len(h.get("kept", [])),
            "class": len(h.get("class_hints", [])),
            "cut": len(h.get("rejected", {})),
            "back": len(h.get("backfilled", [])),
            "cov": h.get("coverage"),
            "folds": len(g.get("folds", [])),
            "hit": g.get("hit_mean"),
            "fp": g.get("fp_mean"),
            "rz": g.get("routed_zero"),
            "passed": g.get("passed"),
            "gated": next((d["gated"] for d in synth_index if t in d["tags"]), None),
        })
    print(pd.DataFrame(rows).to_string(index=False))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["s1", "s2", "s3", "s4", "assemble", "report"])
    ap.add_argument("--tags", default="")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    RUN_DIR.mkdir(parents=True, exist_ok=True)

    if args.stage == "s1":
        asyncio.run(stage_s1(args))
    elif args.stage == "s2":
        asyncio.run(stage_s2(args))
    elif args.stage == "s3":
        stage_s3(args)
    elif args.stage == "s4":
        asyncio.run(stage_s4(args))
    elif args.stage == "assemble":
        stage_assemble(args)
    else:
        stage_report(args)


if __name__ == "__main__":
    main()

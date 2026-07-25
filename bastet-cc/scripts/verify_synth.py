"""End-to-end check that synthesized detectors actually work in the real pipeline.

Loads detectors_synth/index.json, fits routing on the TRAIN-SYN corpus exactly as a
production scan would, routes onto a repo the ground truth marks positive for the
tag, calls the model, and parses. What it proves is narrow but load-bearing: the
generated markdown resolves, the frontmatter parses, routing selects code, and the
model's output survives findings.parse_findings as Finding objects with the right
tag. It is not an accuracy measurement -- S4 is.

  python scripts/verify_synth.py "Liquidation,Governance,ERC1155"
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bastet_cc.findings import parse_findings, to_dict
from bastet_cc.llm import LLMClient
from bastet_cc.prompts import OUTPUT_SCHEMA, build_prompt
from bastet_cc.routing import cost, fit, load_detectors, route
from bastet_cc.runstore import task_id as make_task_id
from bastet_cc.synth import DETECTORS_SYNTH_DIR, PKG_ROOT, index_train_repos

MODEL = "ais3/nemotron-3-ultra-550b"
MAX_TASKS = 6

# Positive (repo, tag) pairs come from the S1 artifact rather than train.csv: it is
# built exclusively from TRAIN-SYN rows, so this script cannot reach a DEV/TEST label
# even by accident, and it keeps the check runnable from the frozen run directory.
S1_PATH = PKG_ROOT / "runs" / "synth" / "s1_localize.json"


async def main() -> None:
    want = (sys.argv[1] if len(sys.argv) > 1 else "Liquidation,Governance,ERC1155").split(",")
    records = json.loads(S1_PATH.read_text())
    repos = sorted({r["repo"] for r in records})
    indexes = index_train_repos(repos)

    dets = load_detectors(DETECTORS_SYNTH_DIR)
    stats = fit(dets, list(indexes.values()))
    print(f"fit(): {stats['n_functions']} functions, vocab {stats['vocab']}, "
          f"{stats['n_broadcast']} detectors would broadcast")

    cl = LLMClient(os.environ["AIS3_BASE_URL"], os.environ["AIS3_API_KEY"], MODEL,
                   max_concurrency=16)
    try:
        for tag in want:
            det = next(d for d in dets if tag in d.tags)
            # A synthesized detector is never allowed to broadcast (DESIGN §2.3 S3.6);
            # if fit() left it too generic to route, that is a finding in itself.
            if det.broadcast:
                print(f"\n[{tag}] WARNING fit() marked broadcast "
                      f"(signature={sorted(det.signature or [])}) -- forced off")
                det.broadcast = False
            repo = sorted({r["repo"] for r in records if tag in r["tags"]})[0]
            tasks = route([det], indexes[repo])
            tasks.sort(key=lambda t: (-len(t.slices), t.path))
            tasks = tasks[:MAX_TASKS]
            c = cost(tasks)
            print(f"\n[{tag}] detector={det.id} gated_repo={repo} "
                  f"signature={len(det.signature or [])} "
                  f"tasks={len(tasks)} slices={c['slices']} "
                  f"input_tokens~{c['input_tokens']}")
            if not tasks:
                print("  ROUTED NOTHING")
                continue
            results = await cl.complete_many([
                {"system": s, "user": u, "schema": OUTPUT_SCHEMA,
                 "task_id": make_task_id(t, MODEL, "v1")}
                for t, (s, u) in ((t, build_prompt(t, None)) for t in tasks)])
            found = []
            for t, r in zip(tasks, results):
                found.extend(parse_findings(t, r))
            errs = [r.error for r in results if r.error]
            print(f"  calls={len(results)} errors={errs or 'none'} findings={len(found)}")
            for f in found[:3]:
                d = to_dict(f)
                print(f"   - {d['tag']} / {d['subtag']} [{d['severity']}] "
                      f"{d['path']}:{d['contract']}.{d['function']} "
                      f"conf={d['confidence']} evidence={d['evidence']!r}")
                print(f"     {d['description'][:200]}")
            assert all(f.tag == tag for f in found), "tag must come from the detector"
    finally:
        await cl.aclose()


if __name__ == "__main__":
    asyncio.run(main())

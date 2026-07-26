#!/usr/bin/env python3
"""Command line entry point for ARBITER runs and scoring."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from arbiter.run import load_evalset, run_arbiter, truth_map  # noqa: E402
from arbiter.score import (  # noqa: E402
    bootstrap_delta,
    constant_yes_baseline,
    mcnemar_exact,
    summarise_runs,
)


def main() -> int:
    ap = argparse.ArgumentParser(prog="arbiter")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run ARBITER over an evaluation set")
    r.add_argument("--evalset", type=Path, required=True)
    r.add_argument("--model", required=True)
    r.add_argument("--run-id", required=True)
    r.add_argument("--out", type=Path, default=Path("runs"))
    r.add_argument("--repeats", type=int, default=1)
    r.add_argument("--concurrency", type=int, default=8)
    r.add_argument("--max-turns", type=int, default=16)
    r.add_argument("--max-tokens", type=int, default=4096)
    r.add_argument("--rpm", type=int, default=110)

    s = sub.add_parser("score", help="score one arm's summary against ground truth")
    s.add_argument("--summary", type=Path, required=True)
    s.add_argument("--evalset", type=Path, required=True)

    c = sub.add_parser("compare", help="paired comparison of two arms")
    c.add_argument("--a", type=Path, required=True, help="baseline arm summary")
    c.add_argument("--b", type=Path, required=True, help="challenger arm summary")
    c.add_argument("--evalset", type=Path, required=True)
    c.add_argument("--out", type=Path)

    args = ap.parse_args()

    if args.cmd == "run":
        summary = run_arbiter(
            evalset=args.evalset,
            model=args.model,
            run_id=args.run_id,
            out_dir=args.out,
            repeats=args.repeats,
            concurrency=args.concurrency,
            max_turns=args.max_turns,
            max_tokens=args.max_tokens,
            rpm=args.rpm,
        )
        _, items = load_evalset(args.evalset)
        truth = truth_map(items)
        runs = list(summary["predictions_by_repeat"].values())
        agg = summarise_runs(runs, truth)
        summary["scored"] = agg
        Path(args.out / f"{args.run_id}.summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8"
        )
        print(json.dumps({k: agg[k] for k in ("TP", "TN", "FP", "FN", "precision",
                                              "recall", "specificity", "f1", "mcc")
                          if k in agg}, indent=1))
        print(f"usage: {json.dumps(summary['usage'])}")
        return 0

    if args.cmd == "score":
        summary = json.loads(args.summary.read_text(encoding="utf-8"))
        _, items = load_evalset(args.evalset)
        truth = truth_map(items)
        runs = list(summary["predictions_by_repeat"].values())
        print(json.dumps(summarise_runs(runs, truth), indent=1))
        return 0

    if args.cmd == "compare":
        a = json.loads(args.a.read_text(encoding="utf-8"))
        b = json.loads(args.b.read_text(encoding="utf-8"))
        _, items = load_evalset(args.evalset)
        truth = truth_map(items)
        a_runs = list(a["predictions_by_repeat"].values())
        b_runs = list(b["predictions_by_repeat"].values())
        floor = constant_yes_baseline(truth)
        report = {
            "evalset": str(args.evalset),
            "n_samples": len(truth),
            "constant_yes_floor": floor.as_dict(),
            "arm_a": {"name": a.get("arm"), "model": a.get("model"),
                      "scored": summarise_runs(a_runs, truth),
                      "usage": a.get("usage")},
            "arm_b": {"name": b.get("arm"), "model": b.get("model"),
                      "scored": summarise_runs(b_runs, truth),
                      "usage": b.get("usage")},
            "same_model": a.get("model") == b.get("model"),
            "mcnemar_first_repeat": mcnemar_exact(a_runs[0], b_runs[0], truth),
            "bootstrap_f1": bootstrap_delta(a_runs[0], b_runs[0], truth, "f1"),
        }
        text = json.dumps(report, ensure_ascii=False, indent=1)
        if args.out:
            args.out.write_text(text, encoding="utf-8")
        print(text)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

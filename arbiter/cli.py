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
    constant_no_baseline,
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
    r.add_argument("--attempts", type=int, default=1,
                   help="independent audit attempts per sample; unioned, stops on first proof")
    r.add_argument("--concurrency", type=int, default=8)
    r.add_argument("--max-turns", type=int, default=26)
    r.add_argument("--max-tokens", type=int, default=4096)
    r.add_argument("--rpm", type=int, default=45)
    r.add_argument("--carry-ruled-out", action="store_true",
                   help="carry failed hypotheses between attempts (measured harmful; off)")
    r.add_argument("--proposals", type=Path, default=None,
                   help="Bastet jobs.jsonl; enables cascade mode (detector hits become hypotheses)")

    a = sub.add_parser(
        "audit", help="audit .sol files directly, no evaluation set or labels needed"
    )
    a.add_argument("paths", type=Path, nargs="+", help=".sol files or directories")
    a.add_argument("--model", default="ais3/nemotron-3-ultra-550b")
    a.add_argument("--run-id", default="audit")
    a.add_argument("--out", type=Path, default=Path("runs"))
    a.add_argument("--attempts", type=int, default=2)
    a.add_argument("--max-turns", type=int, default=26)
    a.add_argument("--concurrency", type=int, default=6)
    a.add_argument("--rpm", type=int, default=45)

    s = sub.add_parser("score", help="score one arm's summary against ground truth")
    s.add_argument("--summary", type=Path, required=True)
    s.add_argument("--evalset", type=Path, required=True)

    ba = sub.add_parser("bastet", help="run the Bastet baseline arm")
    ba.add_argument("--evalset", type=Path, required=True)
    ba.add_argument("--prompts", type=Path, required=True)
    ba.add_argument("--model", required=True)
    ba.add_argument("--run-id", required=True)
    ba.add_argument("--out", type=Path, default=Path("runs"))
    ba.add_argument("--repeats", type=int, default=1)
    ba.add_argument("--concurrency", type=int, default=12)
    ba.add_argument("--max-tokens", type=int, default=4096)
    ba.add_argument("--rpm", type=int, default=45)

    rc = sub.add_parser(
        "reconstruct", help="restore compilation context for non-compiling samples"
    )
    rc.add_argument("--evalset", type=Path, required=True)
    rc.add_argument("--out", type=Path, required=True)
    rc.add_argument("--model", default="ais3/nemotron-3-ultra-550b")
    rc.add_argument("--rpm", type=int, default=45)

    bm = sub.add_parser(
        "bench", help="verify authored pairs and emit an evalset of the admitted ones"
    )
    bm.add_argument("--pairs", type=Path, required=True)
    bm.add_argument("--out", type=Path, required=True)
    bm.add_argument("--note", default="")
    bm.add_argument("--strict", action="store_true",
                    help="require honest_body, matching the bar the agent is held to")

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
            attempts=args.attempts,
            concurrency=args.concurrency,
            max_turns=args.max_turns,
            max_tokens=args.max_tokens,
            rpm=args.rpm,
            proposals_path=args.proposals,
            carry_ruled_out=args.carry_ruled_out,
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

    if args.cmd == "audit":
        # Real-world use: no ground truth, so nothing is scored. The output is the
        # findings and the exploit that backs each one.
        sols: list[Path] = []
        for p in args.paths:
            sols.extend(sorted(p.rglob("*.sol")) if p.is_dir() else [p])
        if not sols:
            print("no .sol files found")
            return 1
        tmp = args.out / f"{args.run_id}.input.json"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps({
            "meta": {"source": "audit", "n": len(sols)},
            "items": [
                {"id": f.stem, "label": "unknown", "code": f.read_text(encoding="utf-8")}
                for f in sols
            ],
        }, ensure_ascii=False), encoding="utf-8")
        print(f"auditing {len(sols)} contract(s)")
        summary = run_arbiter(
            evalset=tmp, model=args.model, run_id=args.run_id, out_dir=args.out,
            repeats=1, attempts=args.attempts, concurrency=args.concurrency,
            max_turns=args.max_turns, rpm=args.rpm,
        )
        rows = [
            json.loads(l) for l in
            (args.out / f"{args.run_id}.results.jsonl").read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]
        print()
        for r in rows:
            o = r["outcome"]
            if o["verdict"] != "vulnerable":
                print(f"  CLEAR       {r['sample_id']}")
                continue
            for f in o["findings"]:
                print(f"  VULNERABLE  {r['sample_id']}: {f.get('title','')}")
                print(f"              function: {f.get('vulnerable_function','')}")
                print(f"              severity: {f.get('severity','')}")
                print(f"              proof:    {f.get('poc_name','')} "
                      f"(executed, predicate satisfied)")
        n_v = sum(1 for r in rows if r["outcome"]["verdict"] == "vulnerable")
        print()
        print(f"{n_v}/{len(rows)} reported vulnerable, each backed by an executed exploit")
        print(f"full transcripts: {args.out / (args.run_id + '.results.jsonl')}")
        print(f"usage: {json.dumps(summary['usage'])}")
        return 0

    if args.cmd == "bastet":
        from arbiter.bastet_arm import run_bastet

        summary = run_bastet(
            evalset=args.evalset,
            prompts_dir=args.prompts,
            model=args.model,
            run_id=args.run_id,
            out_dir=args.out,
            repeats=args.repeats,
            concurrency=args.concurrency,
            max_tokens=args.max_tokens,
            rpm=args.rpm,
        )
        _, items = load_evalset(args.evalset)
        truth = truth_map(items)
        runs = list(summary["predictions_by_repeat"].values())
        agg = summarise_runs(runs, truth)
        summary["scored"] = agg
        (args.out / f"{args.run_id}.summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8"
        )
        print(json.dumps(agg, indent=1))
        print(f"usage: {json.dumps(summary['usage'])}")
        return 0

    if args.cmd == "reconstruct":
        from arbiter.gateway import Gateway
        from arbiter.reconstruct import pair_key, reconstruct_group

        data = json.loads(args.evalset.read_text(encoding="utf-8"))
        items = data["items"]
        gw = Gateway(model=args.model, rpm=args.rpm)

        groups: dict[str, list] = {}
        for item in items:
            groups.setdefault(pair_key(item["id"]), []).append(item)

        rebuilt: dict[str, str] = {}
        report = []
        for key, group in groups.items():
            names = ", ".join(g["id"] for g in group)
            res = reconstruct_group(gw, group, Path("/tmp/arbiter-recon"))
            status = "native" if res.attempts == 0 else ("OK" if res.ok else "FAILED")
            print(f"[{status:6s}] {key:20s} attempts={res.attempts}  {names}")
            if not res.ok:
                print(f"          {res.error}")
            for g in group:
                if res.ok:
                    rebuilt[g["id"]] = res.sources[g["id"]]
            report.append({
                "group": key, "samples": [g["id"] for g in group], "ok": res.ok,
                "attempts": res.attempts, "error": res.error,
                "preserved": res.preserved, "native": res.attempts == 0,
            })

        out_items = []
        for item in items:
            if item["id"] not in rebuilt:
                continue
            new = dict(item)
            new["code"] = rebuilt[item["id"]]
            new["reconstructed"] = any(
                r["group"] == pair_key(item["id"]) and not r["native"] for r in report
            )
            out_items.append(new)

        meta = dict(data.get("meta", {}))
        meta["derived_from"] = str(args.evalset)
        meta["n"] = len(out_items)
        meta["n_vuln"] = sum(1 for i in out_items if i["label"] == "vuln")
        meta["n_safe"] = sum(1 for i in out_items if i["label"] == "safe")
        meta["reconstruction"] = (
            "Samples that did not compile had their stripped compilation context "
            "restored by an LLM under three enforced constraints: additions only, every "
            "significant original line verified present verbatim, and one shared prelude "
            "per vulnerable/patched pair so the pair still differs only by the fix. "
            "Stubs are ours, not the original project's, so reconstructed and natively "
            "compiling samples are reported separately."
        )
        meta["reconstruction_report"] = report
        args.out.write_text(
            json.dumps({"meta": meta, "items": out_items}, ensure_ascii=False, indent=1),
            encoding="utf-8",
        )
        n_ok = sum(1 for r in report if r["ok"])
        print(f"\n{n_ok}/{len(report)} groups usable -> {len(out_items)} samples")
        print(f"usage: {json.dumps(gw.usage.as_dict())}")
        return 0

    if args.cmd == "bench":
        from arbiter.benchmark import build_evalset

        raw = json.loads(args.pairs.read_text(encoding="utf-8"))
        pairs = raw["pairs"] if isinstance(raw, dict) else raw
        meta = build_evalset(
            pairs, Path("/tmp/arbiter-bench"), args.out, source_note=args.note,
            strict=args.strict,
        )
        print(
            f"\n{meta['pairs_admitted']}/{meta['pairs_offered']} pairs admitted "
            f"-> {meta['n']} samples ({meta['n_vuln']} vuln / {meta['n_safe']} safe)"
        )
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
            "constant_no_floor": constant_no_baseline(truth).as_dict(),
            "arm_a": {"name": a.get("arm"), "model": a.get("model"),
                      "scored": summarise_runs(a_runs, truth),
                      "usage": a.get("usage")},
            "arm_b": {"name": b.get("arm"), "model": b.get("model"),
                      "scored": summarise_runs(b_runs, truth),
                      "usage": b.get("usage")},
            "same_model": a.get("model") == b.get("model"),
            "mcnemar_first_repeat": mcnemar_exact(a_runs[0], b_runs[0], truth),
            # Every metric, not just the one we happen to lose. Reporting a confidence
            # interval for F1 alone while promoting MCC and specificity as decisive was
            # selective: the metrics carrying the claim were the ones never given an
            # interval, and MCC's turns out to include zero.
            "bootstrap": {
                m: bootstrap_delta(a_runs[0], b_runs[0], truth, m)
                for m in ("f1", "precision", "recall", "specificity", "accuracy", "mcc")
            },
        }
        text = json.dumps(report, ensure_ascii=False, indent=1)
        if args.out:
            args.out.write_text(text, encoding="utf-8")
        print(text)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

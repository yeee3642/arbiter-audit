"""Bastet+ command line.

    python -m bastet_plus packs
    python -m bastet_plus scan  <path> [--packs slippage,owasp2025] [--samples 3]
    python -m bastet_plus bench [--arms legacy,enhanced] [--model ...]
"""

from __future__ import annotations

import argparse
import dataclasses
import glob
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_PROMPTS = str(ROOT / "prompts" / "legacy")
DEFAULT_CASES = str(ROOT / "benchmark" / "cases")
DEFAULT_LABELS = str(ROOT / "benchmark" / "labels.json")


def _load_dotenv() -> None:
    for name in (".env", ".env.local"):
        p = ROOT / name
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _configs(args):
    from .config import LLMConfig, PipelineConfig
    llm = LLMConfig()
    over = {}
    if getattr(args, "model", None):
        over["model"] = args.model
    if getattr(args, "verifier_model", None):
        over["verifier_model"] = args.verifier_model
    if getattr(args, "concurrency", None):
        over["concurrency"] = args.concurrency
    if getattr(args, "no_cache", False):
        over["cache_enabled"] = False
    if over:
        llm = dataclasses.replace(llm, **over)

    pipe = PipelineConfig()
    pover = {}
    for name in ("samples", "vote_threshold", "max_slice_chars", "min_severity", "verify_votes"):
        v = getattr(args, name, None)
        if v is not None:
            pover[name] = v
    if getattr(args, "no_verify", False):
        pover["verify"] = False
    if getattr(args, "no_slice", False):
        pover["slice_code"] = False
    if getattr(args, "keep_ungrounded", False):
        pover["drop_ungrounded"] = False
    if pover:
        pipe = dataclasses.replace(pipe, **pover)
    return llm, pipe


def cmd_packs(args) -> int:
    from .detectors import available_packs
    packs = available_packs(args.prompts)
    print(f"{sum(packs.values())} detectors in {len(packs)} packs:\n")
    for name, n in packs.items():
        print(f"  {name:22} {n:3d}")
    return 0


def cmd_scan(args) -> int:
    from .detectors import load_detectors
    from .llm import LLMClient
    from .pipeline import run_enhanced, run_legacy
    from .report import write_all

    llm_cfg, pipe_cfg = _configs(args)
    packs = args.packs.split(",") if args.packs else None
    detectors = load_detectors(args.prompts, packs=packs)
    if not detectors:
        print(f"no detectors matched packs={packs}", file=sys.stderr)
        return 2

    target = pathlib.Path(args.path)
    files = ([str(target)] if target.is_file()
             else sorted(glob.glob(str(target / "**" / "*.sol"), recursive=True)))
    if not files:
        print(f"no .sol files under {target}", file=sys.stderr)
        return 2

    print(f"{len(files)} file(s) x {len(detectors)} detectors | model={llm_cfg.model} "
          f"| pipeline={'legacy' if args.legacy else 'enhanced'}")
    client = LLMClient(llm_cfg)
    all_findings, all_stats = [], []
    for path in files:
        res = (run_legacy(path, detectors, client, llm_cfg) if args.legacy
               else run_enhanced(path, detectors, client, llm_cfg, pipe_cfg))
        all_findings.extend(res.findings)
        all_stats.append(res.stats)
        print(f"  {path}: {len(res.findings)} finding(s)")

    stats = {"files": len(files), "detectors": len(detectors), "model": llm_cfg.model}
    stats.update(client.usage.as_dict(llm_cfg))
    stats["reported"] = len(all_findings)
    formats = [f.strip() for f in args.output_format.split(",")] if args.output_format != "all" \
        else ["json", "csv", "md", "sarif"]
    written = write_all(all_findings, args.output, args.name, formats, stats)
    for w in written:
        print(f"  wrote {w}")
    print(json.dumps(stats, indent=2))
    return 0


def cmd_bench(args) -> int:
    from .bench import run_comparison
    llm_cfg, pipe_cfg = _configs(args)
    arms = tuple(a.strip() for a in args.arms.split(","))
    run_comparison(args.cases, args.labels, args.prompts, llm_cfg, pipe_cfg,
                   args.output, arms, tag=args.tag or "")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bastet_plus", description="Bastet+ smart contract vulnerability harness")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--prompts", default=DEFAULT_PROMPTS)
        sp.add_argument("--model")
        sp.add_argument("--verifier-model", dest="verifier_model")
        sp.add_argument("--concurrency", type=int)
        sp.add_argument("--no-cache", action="store_true")
        sp.add_argument("--samples", type=int, help="self-consistency samples per detector (default 1)")
        sp.add_argument("--vote-threshold", type=float, dest="vote_threshold")
        sp.add_argument("--verify-votes", type=int, dest="verify_votes")
        sp.add_argument("--no-verify", action="store_true")
        sp.add_argument("--no-slice", action="store_true")
        sp.add_argument("--keep-ungrounded", action="store_true")
        sp.add_argument("--max-slice-chars", type=int, dest="max_slice_chars")
        sp.add_argument("--min-severity", dest="min_severity", choices=["low", "medium", "high"])

    sp = sub.add_parser("packs", help="list detector packs")
    sp.add_argument("--prompts", default=DEFAULT_PROMPTS)
    sp.set_defaults(func=cmd_packs)

    sp = sub.add_parser("scan", help="scan a file or directory")
    sp.add_argument("path")
    sp.add_argument("--packs", help="comma-separated pack names (default: all)")
    sp.add_argument("--legacy", action="store_true", help="run the original single-shot pipeline instead")
    sp.add_argument("--output", default="scan_report")
    sp.add_argument("--name", default="report")
    sp.add_argument("--output-format", default="md,json,sarif")
    common(sp)
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("bench", help="A/B the legacy and enhanced pipelines on the labelled benchmark")
    sp.add_argument("--cases", default=DEFAULT_CASES)
    sp.add_argument("--labels", default=DEFAULT_LABELS)
    sp.add_argument("--arms", default="legacy,enhanced")
    sp.add_argument("--output", default="benchmark_results")
    sp.add_argument("--tag", help="suffix for the results filename, for ablation runs")
    common(sp)
    sp.set_defaults(func=cmd_bench)
    return p


def main(argv=None) -> int:
    _load_dotenv()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

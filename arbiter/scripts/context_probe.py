#!/usr/bin/env python3
"""Can the harness compile the contract under audit, in a real repository?

This is the measurement that matters before anything else. On OneSavie's own dataset the
hermetic workspace compiled 0 of 24 contracts, so every verdict it produced was "safe" by
default -- a degenerate predictor, just pointed the other way from a 53-detector OR.

No gateway requests. Pure CPU, so it can use every core.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, os.path.expanduser("~/rig/arbiter"))

from arbiter.repo import SKIP_DIRS, plan_for  # noqa: E402
from arbiter.workspace import Workspace  # noqa: E402

WS_ROOT = Path("/tmp/arbiter-ctx")


def contracts_in(repo: Path) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(".sol"):
                out.append(Path(dirpath) / name)
    return sorted(out)


def probe(args: tuple[str, str, bool]) -> dict:
    path_s, repo_s, hermetic = args
    path, repo = Path(path_s), Path(repo_s)
    started = time.monotonic()
    rec: dict = {"file": path.as_posix(), "repo": repo.name}
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        plan = None if hermetic else plan_for(path, repo_root=repo)
        ws = Workspace(
            WS_ROOT / ("herm" if hermetic else "repo"),
            f"{repo.name}__{path.stem}__{abs(hash(path.as_posix())) % 10**6}",
            source,
            plan=plan,
        )
        try:
            res = ws.prepare_context()
        finally:
            ws.cleanup()
        rec.update(res)
        if plan is not None:
            rec["unresolved"] = plan.unresolved[:6]
            rec["band"] = plan.band
    except Exception as exc:  # noqa: BLE001
        rec.update({"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]})
    rec["s"] = round(time.monotonic() - started, 1)
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repos", nargs="+", type=Path)
    ap.add_argument("--hermetic", action="store_true",
                    help="probe the OLD one-file workspace, for the before/after number")
    ap.add_argument("--limit", type=int, default=0, help="contracts per repo, 0 = all")
    ap.add_argument("--workers", type=int, default=max(2, (os.cpu_count() or 4) - 4))
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    jobs: list[tuple[str, str, bool]] = []
    for repo in args.repos:
        files = contracts_in(repo)
        if args.limit:
            files = files[: args.limit]
        jobs += [(f.as_posix(), repo.as_posix(), args.hermetic) for f in files]

    mode = "hermetic (one file, no dependencies)" if args.hermetic else "in-repo"
    print(f"context probe: {len(jobs)} contracts, {len(args.repos)} repos, mode={mode}")
    print(f"workers={args.workers}\n", flush=True)

    records: list[dict] = []
    started = time.monotonic()
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(probe, j) for j in jobs]
        for n, fut in enumerate(as_completed(futures), 1):
            try:
                rec = fut.result()
            except Exception as exc:  # noqa: BLE001
                rec = {"ok": False, "error": f"worker {type(exc).__name__}: {exc}"}
            records.append(rec)
            if n % 25 == 0 or n == len(jobs):
                ok = sum(1 for r in records if r.get("ok"))
                print(f"  {n}/{len(jobs)}  compiling: {ok} ({ok/n:.1%})", flush=True)

    ok = sum(1 for r in records if r.get("ok"))
    print(f"\ncontracts whose audit context compiles: {ok}/{len(records)} "
          f"({ok/max(1,len(records)):.1%})   wall {time.monotonic()-started:.0f}s")

    by_repo: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
    for r in records:
        slot = by_repo[r.get("repo", "?")]
        slot[1] += 1
        slot[0] += 1 if r.get("ok") else 0
    print()
    for repo, (good, total) in sorted(by_repo.items()):
        bar = "#" * int(20 * good / max(1, total))
        print(f"  {repo[:34]:36s} {good:4d}/{total:<4d} {bar}")

    errs = collections.Counter()
    for r in records:
        if r.get("ok"):
            continue
        msg = str(r.get("error") or "")
        key = "Source not found" if "not found" in msg else msg[:70]
        errs[key or "(no diagnostic)"] += 1
    print("\ntop failure modes:")
    for msg, n in errs.most_common(12):
        print(f"  {n:5d}  {msg}")

    if args.out:
        args.out.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in records),
            encoding="utf-8",
        )
        print(f"\nrecords -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

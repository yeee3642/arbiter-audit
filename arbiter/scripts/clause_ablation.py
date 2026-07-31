#!/usr/bin/env python3
"""Are the clauses of the success condition doing anything, or are they decoration?

`victim_loss` rejects an exploit when any of three things is true:

    if (recoveredB >= recoveredA || attackGain == 0 || attackGain < shortfall) revert;
    //  (1) the user was not harmed  (2) nothing was gained  (3) the attacker is not
    //                                     holding what the user lost

Clause (1) is the obvious one and the one anybody would write first. (2) and (3) were
added later, each after an agent talked the previous version into a false positive, and
"we added a clause and the false positives went away" is exactly the kind of claim that
should not be taken on trust. So it is measured.

Every adjudicated `victim_loss` PoC this project has recorded is recompiled and re-run
under each variant of the condition, with everything else byte-identical. The number that
matters is the last column: how many PATCHED halves pass. A patched contract that
satisfies the predicate is a false positive by construction -- the defect is not there.

`none` is a control, not a variant. It re-runs the unmodified file and must reproduce the
verdict already on record; if it does not, nothing below it means anything.

    scripts/clause_ablation.py --run refixed2 --workers 16 [--limit 40]

Costs no gateway requests. Needs forge.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.workspace import Workspace  # noqa: E402

COND_RE = re.compile(
    r"if\s*\(\s*recoveredB\s*>=\s*recoveredA\s*\|\|\s*attackGain\s*==\s*0"
    r"\s*\|\|\s*attackGain\s*<\s*shortfall\s*\)")

VARIANTS = {
    "none": None,
    "drop (1) harm": "if (attackGain == 0 || attackGain < shortfall)",
    "drop (2) gain": "if (recoveredB >= recoveredA || attackGain < shortfall)",
    "drop (3) conservation": "if (recoveredB >= recoveredA || attackGain == 0)",
    "keep only (1) harm": "if (recoveredB >= recoveredA)",
}


def one(job) -> dict:
    sid, name, solidity, target, variant, root = job
    body = solidity if VARIANTS[variant] is None else COND_RE.sub(
        VARIANTS[variant], solidity, count=1)
    if VARIANTS[variant] is not None and body == solidity:
        return {"sample": sid, "poc": name, "variant": variant, "skipped": True}
    d = Path(tempfile.mkdtemp(dir=root))
    try:
        ws = Workspace(d, sid[:50], target)
        pname = ws.write_poc("Ablate", body)
        if not ws.build().ok:
            return {"sample": sid, "poc": name, "variant": variant,
                    "built": False, "passed": False}
        out = ws.run_poc(pname).combined
        passed = any(l.strip().startswith("[PASS]") for l in out.splitlines())
        return {"sample": sid, "poc": name, "variant": variant,
                "built": True, "passed": passed}
    except Exception as exc:  # noqa: BLE001
        return {"sample": sid, "poc": name, "variant": variant,
                "error": f"{type(exc).__name__}: {exc}"[:120]}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="refixed2")
    ap.add_argument("--evalset", type=Path,
                    default=Path("evalsets/v3_authored.json"))
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", type=Path, default=Path("runs/clause_ablation.json"))
    ap.add_argument("--root", type=Path, default=Path.home() / "ablate-tmp")
    args = ap.parse_args()

    if not shutil.which("forge"):
        print("forge is not on PATH; every row here is produced by executing something.")
        return 2

    code = {it["id"]: it["code"] for it in
            json.loads(args.evalset.read_text(encoding="utf-8"))["items"]}

    # Keyed by occurrence, not by name. Three attempts on one sample routinely write
    # the same PoC name, and keying on (sample, name) silently kept only the last --
    # which made the control disagree with itself and looked like a reproduction
    # failure in the harness rather than a bug in this script.
    recorded: dict[str, bool] = {}
    jobs = []
    args.root.mkdir(parents=True, exist_ok=True)
    seen = 0
    for line in Path(f"runs/{args.run}.results.jsonl").read_text(
            encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        sid = r["sample_id"]
        if sid not in code:
            continue
        for p in (r.get("outcome") or {}).get("pocs", []):
            if not p.get("adjudicated") or p.get("predicate") != "victim_loss":
                continue
            if not COND_RE.search(p.get("solidity") or ""):
                continue
            seen += 1
            if args.limit and seen > args.limit:
                break
            key = f"{sid}#{seen}"
            recorded[key] = bool(p.get("passed"))
            for v in VARIANTS:
                jobs.append((sid, key, p["solidity"], code[sid],
                             v, str(args.root)))

    print(f"{len(recorded)} adjudicated victim_loss PoCs x {len(VARIANTS)} variants "
          f"= {len(jobs)} executions\n")

    results = []
    done = 0
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(one, j) for j in jobs]
        for f in as_completed(futs):
            results.append(f.result())
            done += 1
            if done % 100 == 0:
                print(f"  {done}/{len(jobs)}")

    # ---- the control has to hold before anything else is read ---------------------
    ctrl = [r for r in results if r["variant"] == "none" and "passed" in r]
    agree = sum(1 for r in ctrl if r["passed"] == recorded[r["poc"]])
    print(f"\ncontrol: unmodified file reproduces the recorded verdict "
          f"{agree}/{len(ctrl)}")
    if ctrl and agree / len(ctrl) < 0.95:
        print("  the control does not reproduce. Nothing below this line is usable.")

    print(f"\n{'variant':<24}{'passes':>8}{'of':>6}{'  on V_ (real)':>16}"
          f"{'  on S_ (FALSE POSITIVE)':>26}")
    print("-" * 82)
    rows = {}
    for v in VARIANTS:
        got = [r for r in results if r["variant"] == v and "passed" in r]
        passed = [r for r in got if r["passed"]]
        vp = sum(1 for r in passed if r["sample"].startswith("V_"))
        sp = sum(1 for r in passed if r["sample"].startswith("S_"))
        rows[v] = {"ran": len(got), "passed": len(passed), "V": vp, "S": sp}
        print(f"{v:<24}{len(passed):>8}{len(got):>6}{vp:>16}{sp:>26}")

    base = rows["none"]
    print(f"\nEach clause is justified by the last column. Removing it lets "
          f"{'; '.join(f'{v}: +{rows[v]['S'] - base['S']}' for v in VARIANTS if v != 'none')}"
          f" patched contracts through.")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(
        {"run": args.run, "summary": rows, "results": results}, indent=1),
        encoding="utf-8")
    print(f"\n  {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

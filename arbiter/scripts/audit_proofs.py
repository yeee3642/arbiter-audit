#!/usr/bin/env python3
"""Audit every exploit this project has ever called proven.

Two false positives were found by hand today -- one drained a mock the agent had written
itself, one escaped the predicate entirely by calling selfdestruct in its setup -- and
both passed the gate that existed at the time. That is enough to make every earlier
"proven" suspect, and a project whose whole claim is that evidence beats assertion cannot
leave its own evidence unchecked.

Four checks, all mechanical, no model involved:

  1. REPRODUCES -- recompile and re-run the exact stored file. Evidence that cannot be
     replayed is an assertion with extra steps.
  2. NEGATION -- run it again with the attack REMOVED. This is the decisive one. A real
     exploit must fail when the attack is taken out; if the test still passes, whatever
     satisfied the predicate was not the attack. It catches every class at once: a halted
     transaction, ether forced in during setup, profit drawn from scenery, a differential
     that was vacuous.
  3. HALTS -- does the test body call selfdestruct outside the attacker contract, which
     ends the transaction and skips every harness check below it.
  4. PATCHED -- was the sample the FIXED half of an authored pair. In a paired benchmark
     that is a false positive by construction, whatever the exploit did.

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from arbiter.workspace import Workspace  # noqa: E402

RIG = Path(__file__).resolve().parent.parent
WS = Path("/tmp/proof-audit")

# The single line the harness emits to drive a contract-mode attack, and the pranked block
# it emits for an EOA-mode one. Removing them is what "the attack did not happen" means.
ATTACK_CALL = "atk.attack();"
PRANK_OPEN = re.compile(r"vm\.startPrank\(eoa, eoa\);(.*?)vm\.stopPrank\(\);", re.DOTALL)


def load_sources() -> dict[str, str]:
    """Contract sources by sample id, from every evaluation set on disk.

    Older runs predate sources travelling in the result row, so they are recovered from
    the sets they were drawn from rather than skipped.
    """
    out: dict[str, str] = {}
    for path in sorted((RIG / "evalsets").glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for item in data.get("items", []):
            if item.get("id") and item.get("code"):
                out.setdefault(item["id"], item["code"])
    return out


def neuter(solidity: str) -> tuple[str, bool]:
    """Remove the attack, leaving setup, honest baseline and predicate untouched."""
    if ATTACK_CALL in solidity:
        return solidity.replace(ATTACK_CALL, "/* attack removed by audit */"), True
    match = PRANK_OPEN.search(solidity)
    if match and match.group(1).strip():
        return (
            solidity[:match.start(1)] + "\n/* attack removed by audit */\n"
            + solidity[match.end(1):],
            True,
        )
    return solidity, False


def _passes(result) -> bool:
    return any(l.strip().startswith("[PASS]") for l in result.combined.splitlines())


def audit_one(job: tuple[str, str, str, str, str]) -> dict:
    run, sample_id, name, solidity, source = job
    rec: dict = {
        "run": run, "sample_id": sample_id, "poc": name,
        # An id beginning with S_ is the patched half of an authored pair. Nothing an
        # exploit does there can be a true positive.
        "patched_sample": sample_id.startswith("S_") or sample_id.startswith("S1"),
        # selfdestruct anywhere outside a declared contract body ends the transaction and
        # skips the harness's checks.
        "halts": bool(re.search(r"function\s+(?:testArbiterExploit|arbiterRun)[\s\S]*?"
                                r"selfdestruct\s*\(", solidity)),
    }
    if not source:
        rec["error"] = "source for this sample is not on disk"
        return rec

    ws = Workspace(WS, f"{run}_{sample_id}_{name}"[:80], source)
    try:
        ws.write_poc("Replay", solidity)
        if not ws.build().ok:
            rec["reproduces"] = False
            rec["note"] = "stored exploit no longer compiles"
            return rec
        rec["reproduces"] = _passes(ws.run_poc("ReplayPoc"))

        blank, changed = neuter(solidity)
        if not changed:
            rec["negation"] = "attack call not recognised"
            return rec
        ws.write_poc("Negated", blank)
        if not ws.build().ok:
            rec["negation"] = "neutered variant does not compile"
            return rec
        # The verdict that matters: with the attack gone, the predicate must NOT hold.
        rec["negation"] = "STILL PASSES" if _passes(ws.run_poc("NegatedPoc")) else "fails"
    except Exception as exc:  # noqa: BLE001
        rec["error"] = f"{type(exc).__name__}: {exc}"[:160]
    finally:
        ws.cleanup()
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default=str(RIG / "runs" / "*.results.jsonl"))
    ap.add_argument("--workers", type=int, default=max(2, (os.cpu_count() or 4) - 4))
    ap.add_argument("--out", type=Path, default=Path("/tmp/proof_audit.jsonl"))
    args = ap.parse_args()

    sources = load_sources()
    jobs: list[tuple[str, str, str, str, str]] = []
    for path in sorted(glob.glob(args.runs)):
        run = Path(path).name.replace(".results.jsonl", "")
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            outcome = row.get("outcome") or {}
            if not outcome.get("proven"):
                continue
            source = row.get("source") or sources.get(row.get("sample_id", ""), "")
            for poc in outcome.get("pocs") or []:
                if poc.get("passed") and poc.get("adjudicated"):
                    jobs.append((run, row["sample_id"], poc.get("name", "?"),
                                 poc.get("solidity", ""), source))
                    break

    print(f"auditing {len(jobs)} exploits this project has called proven\n", flush=True)
    records: list[dict] = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(audit_one, j) for j in jobs]
        for n, fut in enumerate(as_completed(futures), 1):
            try:
                records.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                records.append({"error": f"worker {type(exc).__name__}: {exc}"})
            if n % 10 == 0:
                print(f"  {n}/{len(jobs)}", flush=True)

    args.out.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in records), encoding="utf-8"
    )

    survived = [
        r for r in records
        if r.get("reproduces") and r.get("negation") == "fails"
        and not r["patched_sample"] and not r["halts"]
    ]
    print(f"\n{'run':<18} {'sample':<44} repro negation      flags")
    for r in sorted(records, key=lambda x: (x.get("run", ""), x.get("sample_id", ""))):
        flags = []
        if r.get("patched_sample"):
            flags.append("PATCHED-SAMPLE")
        if r.get("halts"):
            flags.append("HALTS")
        if r.get("error"):
            flags.append(r["error"][:40])
        print(f"{r.get('run','?')[:17]:<18} {r.get('sample_id','?')[:43]:<44} "
              f"{str(r.get('reproduces','-')):<5} {str(r.get('negation','-')):<13} "
              f"{','.join(flags)}")

    print(f"\n{'-' * 78}")
    print(f"total called proven          {len(records)}")
    print(f"  reproduce on re-run        {sum(1 for r in records if r.get('reproduces'))}")
    print(f"  on a PATCHED sample        {sum(1 for r in records if r.get('patched_sample'))}")
    print(f"  halt before the predicate  {sum(1 for r in records if r.get('halts'))}")
    print(f"  PASS WITH ATTACK REMOVED   "
          f"{sum(1 for r in records if r.get('negation') == 'STILL PASSES')}")
    print(f"\nsurvive every check          {len(survived)}")
    for r in survived:
        print(f"    {r['run']:<18} {r['sample_id']}")
    reasons = Counter(
        r.get("negation") for r in records if r.get("negation") not in ("fails", None)
    )
    if reasons:
        print("\nnegation could not be applied:")
        for reason, n in reasons.most_common():
            print(f"    {n:4d}  {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

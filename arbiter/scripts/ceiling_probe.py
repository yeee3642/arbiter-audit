#!/usr/bin/env python3
"""How many known-exploitable samples can the strict predicate prove at all?

The benchmark's 35 pairs each carry a reference exploit that was verified to pass on
the vulnerable half and fail on the patched one. Not one of them was proven under
`victim_loss` -- their predicates are eth_profit (24), liveness_broken (7),
state_change (2) and token_profit (2). But `victim_loss` is the only strict predicate,
so it is the ruler the agent is graded with. The ground truth and the instrument are
not the same yardstick, and until this is measured nobody can say whether recall 0.286
is the agent failing to find attacks or the predicate refusing to admit them.

So: take each reference exploit exactly as written, compose it under `victim_loss`, and
run it on both halves. The victim's fragments are split mechanically out of
`honest_body` -- the last statement is how an ordinary user gets their money back, the
rest is how they put it in -- because that is what honest_body already is.

Every outcome is classified, and the classes are the point:

    expressible     passes on the vulnerable half, fails on the patched one. The
                    predicate can prove this class of defect.
    indiscriminate  passes on BOTH halves. Worse than a miss: whatever it proved was
                    not about the defect.
    no_victim       the victim's own round trip returns nothing even with no attack, so
                    there is no user with something to lose. Often correct -- signature
                    replay and predictable randomness have no depositor.
    unharmed        the attack ran and took value out of the contract, but the modelled
                    user was still paid in full. `victim_loss` is stricter than "the
                    attacker stole something" and here the two come apart.
    uncredited      the user did lose, but the attacker is not holding it. Cross-asset
                    attacks land here: collateral in, ether out.
    no_build        the composition did not compile. A harness limit, not a predicate
                    one, and the only class that is purely our fault.

Costs no gateway requests. Run:  python3 scripts/ceiling_probe.py [--workers N]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.workspace import Workspace  # noqa: E402

NOHARM = re.compile(r"ArbiterNoHarm\((\d+)[^,]*,\s*(\d+)[^,]*,\s*(\d+)")
NODRAIN = re.compile(r"ArbiterNotDrained")
NO_TRIAL = re.compile(r"the attack reverted in every environment")


def split_honest(honest: str) -> tuple[str, str]:
    """Enter is everything but the last statement; exit is the last one.

    `honest_body` is already a round trip -- `deposit{value: 3 ether}(); withdraw();` --
    which is exactly the shape victim_loss needs. Statements are split on semicolons at
    brace depth zero so a `{value: ...}` call option does not split the line.
    """
    stmts, depth, cur = [], 0, []
    for ch in honest:
        if ch in "{([":
            depth += 1
        elif ch in "})]":
            depth -= 1
        cur.append(ch)
        if ch == ";" and depth == 0:
            stmts.append("".join(cur).strip())
            cur = []
    tail = "".join(cur).strip()
    if tail:
        stmts.append(tail)
    stmts = [s for s in stmts if s]
    if len(stmts) < 2:
        return ("\n".join(stmts), "")
    return ("\n".join(stmts[:-1]), stmts[-1])


def judge(job: tuple[str, str, str, str, str, str, str]) -> dict[str, Any]:
    slug, vuln_src, patched_src, deploy, attacker, enter, exit_ = job
    out: dict[str, Any] = {"slug": slug}
    if not exit_:
        out["verdict"] = "no_victim"
        out["why"] = "honest_body is a single statement: no round trip to split"
        return out

    def run_half(source: str) -> dict[str, Any]:
        ws = Workspace(Path(tempfile.mkdtemp()), slug[:60], source)
        try:
            sol = ws.compose_victim_loss(
                deploy_code=deploy, victim_enter=enter, victim_exit=exit_,
                attacker_code=attacker, mode="contract",
            )
            name = ws.write_poc("Ceiling", sol)
            build = ws.build()
            if not build.ok:
                first = next(
                    (l.strip() for l in build.combined.splitlines()
                     if l.strip().startswith("Error (")), "unknown"
                )
                return {"ok": False, "reason": "no_build", "detail": first[:120]}
            text = ws.run_poc(name).combined
            if any(l.strip().startswith("[PASS]") for l in text.splitlines()):
                return {"ok": True}
            if NO_TRIAL.search(text):
                return {"ok": False, "reason": "no_victim"}
            if NODRAIN.search(text):
                return {"ok": False, "reason": "not_drained"}
            m = NOHARM.search(text)
            if m:
                a, b, g = (int(m.group(i)) for i in (1, 2, 3))
                if a == 0:
                    return {"ok": False, "reason": "no_victim"}
                if a <= b:
                    return {"ok": False, "reason": "unharmed", "gain": g}
                return {"ok": False, "reason": "uncredited",
                        "shortfall": a - b, "gain": g}
            return {"ok": False, "reason": "unknown", "detail": text[-160:]}
        except ValueError as exc:
            return {"ok": False, "reason": "refused", "detail": str(exc)[:120]}
        except Exception as exc:  # noqa: BLE001 -- one pair must not stop the sweep
            return {"ok": False, "reason": "error",
                    "detail": f"{type(exc).__name__}: {exc}"[:120]}
        finally:
            ws.cleanup()

    on_vuln = run_half(vuln_src)
    out["vuln"] = on_vuln
    if on_vuln["ok"]:
        on_patched = run_half(patched_src)
        out["patched"] = on_patched
        out["verdict"] = "expressible" if not on_patched["ok"] else "indiscriminate"
    else:
        out["verdict"] = on_vuln["reason"]
        out["why"] = on_vuln.get("detail", "")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pairs", type=Path,
                    default=Path(__file__).resolve().parent.parent
                    / "evalsets" / "test_pairs_v2.json")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args()

    pairs = json.loads(args.pairs.read_text(encoding="utf-8"))["pairs"]
    jobs = []
    for p in pairs:
        enter, exit_ = split_honest(p.get("honest_body") or "")
        jobs.append((p["slug"], p["vulnerable_code"], p["patched_code"],
                     p.get("deploy_code") or "", p.get("attacker_code") or "",
                     enter, exit_))

    results: list[dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for fut in as_completed([pool.submit(judge, j) for j in jobs]):
            results.append(fut.result())

    order = ["expressible", "indiscriminate", "unharmed", "uncredited",
             "no_victim", "not_drained", "no_build", "refused", "error", "unknown"]
    results.sort(key=lambda r: (order.index(r["verdict"])
                                if r["verdict"] in order else 99, r["slug"]))
    print(f"{'reference exploit':<50} {'under victim_loss':<16} detail")
    print("-" * 104)
    for r in results:
        detail = r.get("why") or ""
        v = r.get("vuln", {})
        if r["verdict"] == "unharmed":
            detail = f"attacker took {v.get('gain', 0) / 1e18:g} ether, user still paid"
        elif r["verdict"] == "uncredited":
            detail = (f"user short {v.get('shortfall', 0) / 1e18:g}, "
                      f"attacker holds {v.get('gain', 0) / 1e18:g}")
        print(f"{r['slug'][:50]:<50} {r['verdict']:<16} {detail[:36]}")

    print("-" * 104)
    counts: dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    for k in order:
        if counts.get(k):
            print(f"  {k:<16} {counts[k]:>3}")
    ceiling = counts.get("expressible", 0)
    print(f"\n  CEILING: {ceiling} of {len(results)} known-exploitable samples can be "
          f"proven under victim_loss at all.")
    print(f"  Recall is bounded by {ceiling / len(results):.3f}, not by 1.000.")
    if counts.get("indiscriminate"):
        print(f"  WARNING: {counts['indiscriminate']} passed on the PATCHED half too.")
    if args.json:
        args.json.write_text(json.dumps(results, indent=1), encoding="utf-8")
        print(f"\n  detail: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

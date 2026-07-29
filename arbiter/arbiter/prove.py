"""How far a finding got, on a ladder where each rung takes a power away from us.

A finding in this project is never one claim. It is a claim that survived a particular
amount of scepticism, and the useful question is how much.

    1  synthetic    The harness accepted it. The predicate is ours, the negation test
                    ran, the gates held. But the harness is the EVM's administrator: it
                    deployed the contract, built the world, conjured the capital and
                    could impersonate anyone. Every gate in this project exists to keep
                    that power out of the attack, which is an admission that the power
                    is there.

    2  standalone   The dumped project compiles and passes with `forge test` outside the
                    harness, on someone else's machine, with the compiler pinned. The
                    administrator is still present -- but nobody has to trust our
                    summary, because they can run it.

    3  live         Reproduced as signed transactions on a chain. The administrator is
                    gone: there is no `vm`, so acting as an account means holding its
                    key, spending means having the balance, and being included means
                    paying for gas. Nothing is left to forge.

The rungs are not redundant. Rung 1 finds things -- it is the only one that searches.
Rung 3 cannot find anything at all; it can only refuse. Measured on twelve dumped
exploits, rung 3 refused both false positives that rungs 1 and 2 had accepted, and it
refused them on their merits: one left the victim short while handing the attacker
nothing, the other moved no tokens out of the contract at all.

A fourth rung exists and is not on this ladder, because it needs something this ladder
cannot supply: `onchain.py` binds an attack to a contract that is really deployed, with
the storage and liquidity it really has. Local mode shows an ordinary account can do
this; fork mode would show the contract is out there to do it to.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

RUNGS = ("none", "synthetic", "standalone", "live")


def _rung(name: str) -> int:
    return RUNGS.index(name)


def prove_dump(dump_dir: Path, port: int = 9400,
               only: str = "") -> dict[str, Any]:
    """Walk every dumped exploit up the ladder and record where each one stopped."""
    from .live_replay import (
        Untranslatable,
        parse_poc,
        parse_poc_exploit,
        parse_poc_other,
        replay,
        replay_exploit,
        replay_other,
    )

    manifest_path = dump_dir / "manifest.json"
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest_path.is_file() else {"exploits": []}
    )
    standalone = {
        Path(e["path"]).name: bool(e.get("reproduces"))
        for e in manifest.get("exploits", [])
    }

    projects = sorted(p for p in dump_dir.iterdir() if (p / "foundry.toml").is_file())
    if only:
        projects = [p for p in projects if only in p.name]

    findings: list[dict[str, Any]] = []
    for i, proj in enumerate(projects):
        sample = proj.name
        rec: dict[str, Any] = {
            "sample_id": sample,
            # Being in the dump at all means the harness accepted it: `dump` only
            # writes proofs that passed and were adjudicated.
            "synthetic": True,
            "standalone": standalone.get(sample, False),
        }
        target = proj / "src" / "Target.sol"
        pocs = list((proj / "test").glob("*.t.sol"))
        if not target.is_file() or not pocs:
            rec.update({"live": False, "note": "incomplete dump"})
            findings.append(rec)
            continue

        with tempfile.TemporaryDirectory() as tmp:
            live: dict[str, Any] = {}
            for parse, run in (
                (parse_poc, replay),
                (parse_poc_exploit, replay_exploit),
                (parse_poc_other, replay_other),
            ):
                try:
                    live = run(parse(pocs[0], target, sample), Path(tmp), port + i * 4)
                    break
                except Untranslatable:
                    continue
                except Exception as exc:  # noqa: BLE001 -- one sample cannot stop it
                    live = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
                    break
        rec["live"] = bool(live.get("proven"))
        rec["live_detail"] = live
        findings.append(rec)

    for rec in findings:
        rec["reached"] = (
            "live" if rec["live"]
            else "standalone" if rec["standalone"]
            else "synthetic" if rec["synthetic"]
            else "none"
        )

    return {
        "dump": str(dump_dir),
        "findings": findings,
        "by_rung": {
            r: sum(1 for f in findings if f["reached"] == r) for r in RUNGS[1:]
        },
    }


def render(report: dict[str, Any]) -> str:
    findings = report["findings"]
    lines = [
        f"{'finding':<50} {'1 synthetic':>12} {'2 standalone':>13} {'3 live':>8}",
        "-" * 87,
    ]
    for f in sorted(findings, key=lambda x: (-_rung(x["reached"]), x["sample_id"])):
        mark = lambda ok: "  yes" if ok else "   --"  # noqa: E731
        lines.append(
            f"{f['sample_id'][:50]:<50} {mark(f['synthetic']):>12} "
            f"{mark(f['standalone']):>13} {mark(f['live']):>8}"
        )
    lines.append("-" * 87)
    by = report["by_rung"]
    lines.append(
        f"{by['live']} reached a chain, {by['standalone']} stopped at a standalone "
        f"test, {by['synthetic']} only ever held inside the harness"
    )

    # A finding on the patched half of a pair is wrong wherever it got to, so the ladder
    # is only worth anything if the top rung is clean. Say so either way.
    top = [f for f in findings if f["reached"] == "live"]
    bad = [f["sample_id"] for f in top if f["sample_id"].startswith("S_")]
    if bad:
        lines.append(f"WARNING: {len(bad)} of those are the PATCHED half of a pair: "
                     + ", ".join(bad))
    elif top:
        lines.append("every finding that reached a chain was on the vulnerable half "
                     "of its pair")
    return "\n".join(lines)

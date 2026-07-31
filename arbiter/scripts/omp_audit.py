#!/usr/bin/env python3
"""Audit one contract with omp as the agent and ARBITER as the harness.

The control is the project's own loop; the only thing swapped is who chooses the next
tool. Same gateway, same model, same tool surface, same predicate -- so a difference in
the verdict is a difference in the agent and not in what a finding means.

    scripts/omp_audit.py examples/StakingVault.sol --max-turns 26

Needs omp on PATH and forge on PATH, and reads AIS3_API_KEY from ~/.arbiter_env the same
way every other script here does.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

REPO = Path(__file__).resolve().parent.parent

# The task, worded as the project's own loop words it. Kept here rather than imported so
# that a change to ARBITER's prompt does not silently change what the other agent was
# asked -- the two have to be compared on the same question, and if they drift apart that
# should be a visible edit, not an invisible one.
TASK = """You are auditing one Solidity contract for an exploitable vulnerability.

Rules, and they are enforced by the tools rather than by you:

1. You may NOT report a vulnerability from reading alone. A finding is only accepted
   when `run_exploit` has compiled your attack, executed it on a local EVM, and the
   harness's own success condition was satisfied. You never see that condition and you
   cannot change it.
2. `run_exploit` takes the deployment, an attacker contract, and the fragments describing
   what an ordinary user does to take a position and to get it back. The harness runs the
   scenario twice, once with your attack and once without, and admits the finding only if
   the ordinary user recovers strictly less because of you.
3. `run_poc` is exploration only. A passing run_poc can never back a finding.
4. When you have a passing `run_exploit`, call `submit_finding` quoting the offending
   expression verbatim from the source.
5. If you cannot demonstrate an attack, call `conclude_safe` and say what you tested.
   Concluding safe is a correct professional outcome. Reporting something you could not
   demonstrate is not.

Start by reading the contract with `read_source`. Work until you call `submit_finding`
or `conclude_safe`."""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("source", type=Path)
    ap.add_argument("--sample-id", default="")
    ap.add_argument("--run-dir", type=Path, default=Path("/tmp/omp-audit"))
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--predicates", default="")
    args = ap.parse_args()

    src = args.source if args.source.is_absolute() else REPO / args.source
    if not src.is_file():
        print(f"no such contract: {src}")
        return 2
    sample = args.sample_id or src.stem

    run_dir = args.run_dir / sample
    run_dir.mkdir(parents=True, exist_ok=True)
    outcome = run_dir / "outcome.json"
    if outcome.exists():
        outcome.unlink()

    # Project-scoped so nothing here touches the user's global omp config, and so two
    # samples running side by side cannot see each other's tools.
    (run_dir / ".omp").mkdir(exist_ok=True)
    (run_dir / ".omp" / "mcp.json").write_text(json.dumps({
        "mcpServers": {
            "arbiter": {
                "command": sys.executable,
                "args": [
                    str(REPO / "scripts" / "arbiter_mcp.py"),
                    "--source", str(src),
                    "--sample-id", sample,
                    "--root", str(run_dir / "ws"),
                    "--outcome", str(outcome),
                    "--predicates", args.predicates,
                ],
                "cwd": str(REPO),
                # PATH stated rather than inherited. The first run of this bridge left it
                # to inheritance, forge was not on the MCP child's PATH, and the audit
                # came back "safe" on a contract with a live reentrancy. The dispatcher
                # now refuses that outcome, but the right place to not have the problem
                # is here.
                "env": {"PATH": os.environ.get("PATH", "")},
            }
        }
    }, indent=1), encoding="utf-8")

    env = dict(os.environ)
    envfile = Path.home() / ".arbiter_env"
    if envfile.is_file():
        for line in envfile.read_text(encoding="utf-8").splitlines():
            line = line.strip().removeprefix("export ").strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")

    # Resolved rather than trusted to PATH. omp lives under an nvm version directory, so
    # it is on PATH only for a shell that sourced nvm -- and this script is routinely
    # launched by one that did not.
    omp = shutil.which("omp", path=env.get("PATH"))
    if not omp:
        cands = sorted((Path.home() / ".nvm" / "versions" / "node").glob("*/bin/omp"))
        omp = str(cands[-1]) if cands else ""
    if not omp:
        print("omp is not installed, or not under ~/.nvm/versions/node/*/bin.")
        return 2
    env["PATH"] = f"{Path(omp).parent}:{env.get('PATH', '')}"

    started = time.time()
    proc = subprocess.run(
        [omp, "-p", TASK],
        cwd=run_dir, env=env, capture_output=True, text=True,
        timeout=args.timeout,
    )
    elapsed = time.time() - started

    (run_dir / "omp.stdout").write_text(proc.stdout, encoding="utf-8")
    (run_dir / "omp.stderr").write_text(proc.stderr, encoding="utf-8")

    print(f"sample      {sample}")
    print(f"omp exit    {proc.returncode}   {elapsed:.0f}s")
    if not outcome.exists():
        print("verdict     -- no outcome written; the agent never reached a terminal tool")
        print(f"transcript  {run_dir}/omp.stdout")
        return 1

    rec = json.loads(outcome.read_text(encoding="utf-8"))
    calls = rec.get("tool_calls") or []
    used = {}
    for c in calls:
        used[c.get("tool", "?")] = used.get(c.get("tool", "?"), 0) + 1
    print(f"verdict     {rec.get('verdict')}   stop={rec.get('stop_reason') or '-'}")
    print(f"proven      {bool(rec.get('proven'))}")
    print(f"tool calls  {len(calls)}   {used}")
    print(f"findings    {len(rec.get('findings') or [])}"
          f"   rejected {len(rec.get('rejected_submissions') or [])}")
    print(f"outcome     {outcome}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

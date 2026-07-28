#!/usr/bin/env python3
"""Show the full compiler output for one contract's audit context.

The probe reports counts; this shows why a particular one failed, which is what the
resolver has to be fixed against.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.expanduser("~/rig/arbiter"))

from arbiter.repo import plan_for  # noqa: E402
from arbiter.workspace import Workspace  # noqa: E402


def main() -> int:
    target = Path(sys.argv[1]).resolve()
    repo = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None
    plan = plan_for(target, repo_root=repo)

    print(f"target     {target}")
    print(f"repo_root  {plan.repo_root}")
    print(f"band       {plan.band}   floor={plan.floor}   pragma={plan.test_pragma}")
    print(f"external   {plan.external_used}")
    print(f"unresolved {plan.unresolved}")
    print("remappings:")
    for line in plan.remappings:
        print(f"  {line}")

    ws = Workspace(Path("/tmp/arbiter-dbg"), "dbg", target.read_text(errors="ignore"),
                   plan=plan)
    res = ws.prepare_context()
    print(f"\nprepare_context -> {res}")
    print("\nremappings after repair:")
    for line in plan.remappings:
        print(f"  {line}")

    probe = ws.context_ok()
    print(f"\nfinal build ok={probe.ok}")
    print(probe.combined[:6000])
    ws.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())

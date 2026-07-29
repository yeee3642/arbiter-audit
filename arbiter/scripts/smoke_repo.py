#!/usr/bin/env python3
"""End-to-end smoke test of the in-repo workspace, before any gateway request is spent.

Checks the four capabilities an exploit against a real protocol needs: the context
compiles, the repository is navigable, extra imports land in the composed file, and the
composed file itself builds. All CPU, no requests.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from arbiter.repo import plan_for  # noqa: E402
from arbiter.workspace import Workspace  # noqa: E402

REPO = Path(os.path.expanduser("~/Bastet/dataset/repos/2021-12-defiprotocol"))
TARGET = REPO / "contracts/contracts/Basket.sol"


def main() -> int:
    plan = plan_for(TARGET, repo_root=REPO)
    ws = Workspace(Path("/tmp/smoke"), "smoke", TARGET.read_text(errors="ignore"),
                   plan=plan)

    print("1. context")
    print(f"   {ws.prepare_context()}")

    print("\n2. repository is navigable")
    print("   list_repo_files('interfaces'):")
    for line in ws.repo_files("interfaces").splitlines()[:6]:
        print(f"     {line}")
    print("   grep_repo('function initialize'):")
    for line in ws.grep_repo("function initialize").splitlines()[:4]:
        print(f"     {line}")

    print("\n3. compose an exploit with an extra import")
    sol = ws.compose_exploit(
        deploy_code="Basket target = new Basket();",
        predicate="eth_profit",
        mode="eoa",
        attack_body="target.approveUnderlying(address(0xdead));",
        honest_body="{}",
        require_honest=False,
        extra_imports=["@openzeppelin/contracts/token/ERC20/IERC20.sol",
                       "arbiter-repo/contracts/contracts/Factory.sol"],
    )
    for line in sol.splitlines()[:9]:
        print(f"   {line}")

    print("\n4. does the composed exploit build")
    ws.write_poc("Smoke", sol)
    build = ws.build()
    print(f"   build.ok = {build.ok}")
    if not build.ok:
        for line in build.combined.splitlines():
            if "Error" in line or "-->" in line:
                print(f"   {line.strip()[:140]}")
    ws.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())

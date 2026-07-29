#!/usr/bin/env python3
"""Run one recorded exploit at a chosen round count and print what the harness saw.

    python3 scripts/rounds_debug.py runs/x.results.jsonl <fragment-index> <rounds>...
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import arbiter.workspace as W  # noqa: E402
from arbiter.cascade_lib import _fragments  # noqa: E402


def main() -> int:
    path, idx = Path(sys.argv[1]), int(sys.argv[2])
    # "8x10" means eight rounds at ten ether of attacker capital.
    specs = [s.split("x") for s in sys.argv[3:]] or [["1", "10"]]
    rounds = [(int(a), int(b) * 10**18) for a, b in
              ((s[0], s[1] if len(s) > 1 else "10") for s in specs)]
    row = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    frag = _fragments(row)[idx]

    for r, funding in rounds:
        W.VICTIM_ENVIRONMENTS = [(10**19, 0, r)]
        ws = W.Workspace(Path(tempfile.mkdtemp()), "r", row["source"])
        try:
            sol = ws.compose_victim_loss(
                deploy_code=frag.get("deploy_code", ""),
                victim_enter=frag.get("victim_enter", ""),
                victim_exit=frag.get("victim_exit", ""),
                attacker_code=frag.get("attacker_code", ""),
                attack_body=frag.get("attack_body", ""),
                mode=frag.get("mode") or "contract",
                token_expr=frag.get("token_expr", ""),
                funding_wei=funding,
            )
            name = ws.write_poc("R", sol)
            build = ws.build()
            if not build.ok:
                print(f"rounds={r:<3} capital={funding // 10**18:<4} BUILD FAIL")
                continue
            out = ws.run_poc(name).combined
            marks = [
                line.strip()[:100]
                for line in out.splitlines()
                if "ArbiterNoHarm" in line or "[PASS]" in line or "ARBITER:" in line
            ]
            print(f"rounds={r:<3} capital={funding // 10**18:<4} "
                  f"{marks[0] if marks else '(no verdict line)'}")
        finally:
            ws.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Text-level check of the tuple hoist. Proves the rewrite, not that solc accepts it."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.workspace import hoist_tuple_locals, hoist_victim_locals  # noqa: E402

CASES = [
    ("the shape that broke a reference exploit",
     '        (bool okDep, ) = address(target).call{value: 1 ether}(\n'
     '            abi.encodeWithSelector(V.deposit.selector));\n'
     '        require(okDep, "deposit failed");',
     {"okDep": "bool"}, "(okDep, ) ="),

    ("two named components",
     '        (uint256 a, uint256 b) = target.split();',
     {"a": "uint256", "b": "uint256"}, "(a, b) ="),

    ("address payable normalises to address",
     '        (address payable who, ) = target.beneficiary();',
     {"who": "address"}, "(who, ) ="),

    ("bytes memory leaves the whole statement alone",
     '        (bool ok, bytes memory ret) = address(target).call("");',
     {}, "(bool ok, bytes memory ret) ="),

    ("a plain tuple assignment is not a declaration",
     '        (ok, ret) = address(target).call("");',
     {}, "(ok, ret) ="),

    ("the call on the right is never touched",
     '        (bool ok, ) = address(t).call{value: v}(abi.encode(x, y));',
     {"ok": "bool"}, 'abi.encode(x, y)'),
]

fails = 0
for label, src, want_seen, want_in in CASES:
    seen, out = hoist_tuple_locals(src)
    ok = seen == want_seen and want_in in out
    fails += not ok
    print(f"  [{'OK  ' if ok else 'WRONG'}] {label:44s} {seen}")
    if not ok:
        print("        ->", out.strip().replace("\n", " ")[:96])

# End to end through the victim hoist: the name has to reach the exit as arbv_*.
enter = ('        (bool okDep, ) = address(target).call{value: 5 ether}("");\n'
         '        require(okDep, "deposit failed");')
exit_ = '        require(okDep, "did not survive");\n        target.withdraw();'
decls, e2, x2 = hoist_victim_locals(enter, exit_)
ok = ("bool internal arbv_okDep;" in decls
      and "(arbv_okDep, ) =" in e2
      and "require(arbv_okDep," in x2)
fails += not ok
print(f"\n  [{'OK  ' if ok else 'WRONG'}] the name reaches the exit stage")
print("        decls:", decls.strip())
print("        enter:", e2.strip().splitlines()[0])
print("        exit :", x2.strip().splitlines()[0])

print(f"\n{len(CASES) + 1 - fails}/{len(CASES) + 1} as expected  "
      "(text only -- solc has not seen this)")
raise SystemExit(1 if fails else 0)

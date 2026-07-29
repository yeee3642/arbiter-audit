#!/usr/bin/env python3
"""Resolve the repository from this file, not from one machine's home directory.

Thirteen scripts found the package by inserting `~/rig/arbiter` -- and one of them
`/home/ubuntu/rig/arbiter` -- onto sys.path. That is the absolute path on a single box.
Anywhere else the import failed, which mattered most for the probes: the integrity
gates are the part of this project that needs no gateway, no network and no key, and
are therefore the part a reader can check for themselves. On a fresh clone they did not
run at all.

Idempotent. Run from the repository root:  python3 scripts/derig.py
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = "Path(__file__).resolve().parent.parent"

SYS_PATH = re.compile(
    r'^sys\.path\.insert\(0,\s*os\.path\.expanduser\("~/rig/arbiter"\)\)\s*$', re.M
)
RIG_CONST = re.compile(
    r'^RIG\s*=\s*Path\(\s*(?:os\.path\.expanduser\("~/rig/arbiter"\)'
    r'|"/home/ubuntu/rig/arbiter")\s*\)\s*$',
    re.M,
)
SH_CD = re.compile(r'^cd "\$HOME/rig/arbiter" \|\| exit 1\s*$', re.M)
SH_REPLACEMENT = 'cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1'


def main() -> int:
    scripts = Path(__file__).resolve().parent
    changed: list[str] = []
    for path in sorted(scripts.iterdir()):
        if path.suffix not in (".py", ".sh") or path.name == "derig.py":
            continue
        original = path.read_text(encoding="utf-8")
        text = original
        if path.suffix == ".sh":
            text = SH_CD.sub(SH_REPLACEMENT, text)
        else:
            text = SYS_PATH.sub(f"sys.path.insert(0, str({REPO}))", text)
            text = RIG_CONST.sub(f"RIG = {REPO}", text)
            # Several of these reached for os.path only to build that one path, and
            # some never imported Path at all.
            if REPO in text and "from pathlib import Path" not in text:
                text = text.replace("import sys\n", "import sys\nfrom pathlib import Path\n", 1)
        if text != original:
            path.write_text(text, encoding="utf-8")
            changed.append(path.name)

    print(f"patched {len(changed)} file(s)")
    for name in changed:
        print(f"  {name}")
    left = [
        f"{p.name}:{i}"
        for p in scripts.iterdir()
        if p.suffix in (".py", ".sh")
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if "rig/arbiter" in line and p.name != "derig.py"
    ]
    print(f"remaining hardcoded references: {len(left)}")
    for ref in left:
        print(f"  {ref}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

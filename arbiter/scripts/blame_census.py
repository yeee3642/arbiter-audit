#!/usr/bin/env python3
"""Every compile error in a run, and whose fault it is.

An error census counts strings. It cannot tell a defect in the harness from a mistake by
the agent, and the two want opposite responses: one is a bug to fix, the other is at most
a sentence of guidance and often not even that. Two runs were read as harness regressions
on the strength of a counted string and were not.

So this attributes instead of counting. Three things decide it:

  * **free-form or composed.** `run_poc` writes the agent's file out verbatim -- the
    harness composes nothing and rewrites nothing -- so an error in one of those is the
    agent's by construction. Only `run_exploit` builds a file.
  * **where the line came from.** The composed file is agent fragments inside a harness
    template. A line inside `arbSetup`/`arbEnter`/`arbExit`/the attacker block came from
    the agent; a line in the template did not, and an error there is ours.
  * **what the identifier is,** for the undeclared row specifically: a name the agent
    declared in its own fragment and the harness then lost is a harness defect; a name
    nothing ever declared is the agent's.

Reads `runs/<run>.results.jsonl`. No gateway requests, no forge.
"""

from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# `Error (7576): Undeclared identifier.` then `  --> test/X.t.sol:72:26:` then a caret run
# whose width is the identifier.
ERR_RE = re.compile(
    r"(Error|Warning) \((\d+)\): ([^\n]*)\n\s*--> (\S+?):(\d+):(\d+):"
    r"(?:.*?\n\s*\|\n\s*\d+ \|[^\n]*\n\s*\|\s*(\^+))?",
    re.S,
)

# The template's own function bodies are the agent's fragments verbatim; everything else
# between them is harness text.
FRAGMENT_FNS = ("arbSetup", "arbEnter", "arbExit", "arbAttack", "arbDeploy")


def agent_region(lines: list[str]) -> set[int]:
    """1-based line numbers that came from the agent rather than from the template.

    The attacker block sits above `contract TestArbiterVictim`, and each fragment sits in
    the body of the function the template drops it into.
    """
    region: set[int] = set()
    harness_starts = None
    for i, line in enumerate(lines, 1):
        # Both templates: TestArbiterVictim for victim_loss, TestArbiterExploit for the
        # rest. Matching only the first was how a real defect got filed under the wrong
        # heading -- the file was all agent code and the region came back empty.
        if line.startswith("contract TestArbiter"):
            harness_starts = i
            break
    if harness_starts:
        # Everything above the harness contract other than the fixed preamble.
        for i in range(1, harness_starts):
            region.add(i)
    depth = 0
    inside = False
    for i, line in enumerate(lines, 1):
        if not inside and any(f"function {fn}(" in line for fn in FRAGMENT_FNS):
            inside, depth = True, 0
        if inside:
            depth += line.count("{") - line.count("}")
            region.add(i)
            if depth <= 0 and "{" in "".join(lines[i - 1:i]):
                inside = False
    return region


def blame(poc: dict, code: str, msg: str, path: str, line: int, ident: str,
          lines: list[str], region: set[int]) -> str:
    name = str(poc.get("name") or "")
    if not path.endswith(f"{name}.t.sol"):
        return "agent: error inside a file it asked the harness to import"
    if line not in region:
        return "HARNESS: the line is template, not a fragment"

    src = lines[line - 1] if 0 < line <= len(lines) else ""
    whole = "\n".join(lines)
    if code == "7576" and ident:
        if ident.startswith("_Arbiter"):
            # A name the HARNESS taught, in a template that does not declare it.
            return "HARNESS: an idiom the harness taught, undeclared in this template"
        # What a lost hoist looks like, and only that: the harness stripped the type, so
        # the name survives as an assignment AT STATEMENT START and is typed nowhere. A
        # name simply never declared -- `address(user1).transfer(...)` with no `user1`
        # anywhere -- does not match, and an earlier, looser version of this test filed
        # ten of those against the harness.
        assigned = re.search(rf"^\s*{re.escape(ident)}\s*=(?!=)", whole, re.M)
        # The modifiers have to be here. `address public user1;` is a declaration, in the
        # agent's own Attacker contract, and a version of this test that did not know the
        # word `public` reported six cross-contract scope confusions as lost hoists.
        typed = re.search(
            rf"^\s*[A-Za-z_][\w.]*(?:\[\])?\s+"
            rf"(?:(?:memory|storage|calldata|public|private|internal|constant"
            rf"|immutable|payable)\s+)*{re.escape(ident)}\b", whole, re.M)
        if assigned and not typed:
            return "HARNESS: assigned but never declared -- a lost hoist"
        return "agent: used a name it never declared"
    if code in ("7006", "2622", "2314", "9553"):
        if "new " in src or "{value:" in src or "{ value:" in src:
            return "agent: call-option syntax"
    if code in ("7398", "9640"):
        return "agent: cast through the wrong address-payability"
    if code == "9582":
        return "agent: called a member the target does not have"
    return f"agent: {msg.strip()[:40]}"


def main() -> int:
    for run in sys.argv[1:] or ["refixed2"]:
        path = ROOT / "runs" / f"{run}.results.jsonl"
        rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()
                if l.strip()]
        verdict: collections.Counter = collections.Counter()
        by_code: dict[str, collections.Counter] = collections.defaultdict(
            collections.Counter)
        samples: dict[str, list[str]] = collections.defaultdict(list)
        free = 0

        for row in rows:
            for poc in (row.get("outcome") or {}).get("pocs", []):
                if poc.get("compiled"):
                    continue
                out = poc.get("output_tail") or ""
                lines = (poc.get("solidity") or "").splitlines()
                if not poc.get("adjudicated"):
                    free += len([m for m in ERR_RE.finditer(out) if m.group(1) == "Error"])
                    continue
                region = agent_region(lines)
                for m in ERR_RE.finditer(out):
                    kind, code, msg, f, ln, _col, caret = m.groups()
                    if kind != "Error":
                        continue
                    ln = int(ln)
                    src = lines[ln - 1] if 0 < ln <= len(lines) else ""
                    ident = ""
                    if caret and 0 < ln <= len(lines):
                        col = int(_col)
                        ident = src[col - 1:col - 1 + len(caret)].strip()
                    who = blame(poc, code, msg, f, ln, ident, lines, region)
                    verdict[who] += 1
                    by_code[who][f"{code} {msg.strip()[:46]}"] += 1
                    if len(samples[who]) < 3:
                        samples[who].append(f"{poc['name']}:{ln}  {src.strip()[:92]}")

        total = sum(verdict.values())
        print(f"=== {run}: {total} errors in harness-composed PoCs "
              f"({free} more in free-form ones, the agent's own file) ===\n")
        for who, n in verdict.most_common():
            mark = "***" if who.startswith("HARNESS") else "   "
            print(f"{mark} {n:4d}  {who}")
            for k, v in by_code[who].most_common(4):
                print(f"           {v:3d}  {k}")
            for s in samples[who]:
                print(f"                {s}")
            print()
        ours = sum(n for w, n in verdict.items() if w.startswith("HARNESS"))
        print(f"  harness: {ours}    agent: {total - ours}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

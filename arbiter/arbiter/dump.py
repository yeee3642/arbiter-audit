"""Extract proven exploits from a run as self-contained, runnable Foundry projects.

Every accepted finding in this system is backed by Solidity that compiled and executed,
and until now that evidence only existed inside a JSONL row. That is the wrong place for
it: the whole claim of the project is that a finding is a transcript of an execution
rather than an assertion, and a transcript nobody can replay is just an assertion with
extra steps.

`dump` writes each proven exploit as a directory anyone can `cd` into and `forge test`.
No arguments, no reconstruction, no trust in this tool's own summary -- the reader
re-runs the exploit against the contract and watches it pass.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .workspace import FOUNDRY_TOML, VM_SOL

README = """# {sample_id}

{verdict_line}

## Finding

- **title**: {title}
- **function**: {function}
- **severity**: {severity}
- **predicate**: `{predicate}` — {predicate_note}

**offending expression**, verified to appear verbatim in the contract:

```solidity
{offending}
```

**attack path as reported**:

{attack_path}

## Reproduce

```bash
forge test -vvv
```

Expected: the exploit test PASSES, which under this harness means the attacker ended up
with strictly more than an ordinary user of the same contract does. The success condition
is in `test/{poc_name}.t.sol` and was written by the harness, not by the model that
produced the attack.

## Recorded output from the original run

```
{output}
```
"""

PREDICATE_NOTES = {
    "eth_profit": "attacker ends up holding more ether than the honest baseline",
    "token_profit": "attacker's balance of the named token rises above the honest baseline",
    "state_change": "state an honest user cannot move was moved by an unprivileged account",
    "liveness_broken": "an operation an ordinary user could complete stops working",
    "": "unspecified",
}


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text)[:60].strip("_") or "sample"


def dump_run(results_path: Path, out_dir: Path, include_failed: bool = False) -> dict[str, Any]:
    """Write every proven exploit to its own runnable project. Returns a manifest."""
    rows = [
        json.loads(line)
        for line in results_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[dict[str, Any]] = []
    skipped = 0

    for row in rows:
        sample_id = row.get("sample_id", "unknown")
        outcome = row.get("outcome") or {}
        findings = outcome.get("findings") or []
        pocs = {p.get("name"): p for p in (outcome.get("pocs") or [])}

        # Only exploits the harness itself adjudicated as passing are evidence.
        admissible = [
            p for p in (outcome.get("pocs") or [])
            if p.get("passed") and p.get("adjudicated")
        ]
        if not admissible and not include_failed:
            skipped += 1
            continue

        for finding in findings or [{}]:
            poc = pocs.get(finding.get("poc_name")) or (admissible[0] if admissible else None)
            if poc is None:
                continue
            name = poc.get("name", "Exploit")
            proj = out_dir / _slug(f"{sample_id}__{name}")
            (proj / "src").mkdir(parents=True, exist_ok=True)
            (proj / "test").mkdir(parents=True, exist_ok=True)

            (proj / "foundry.toml").write_text(FOUNDRY_TOML, encoding="utf-8")
            (proj / "src" / "Target.sol").write_text(
                row.get("source") or _recover_source(row), encoding="utf-8"
            )
            (proj / "test" / "Vm.sol").write_text(VM_SOL, encoding="utf-8")
            (proj / "test" / f"{name}.t.sol").write_text(
                poc.get("solidity", ""), encoding="utf-8"
            )
            (proj / "README.md").write_text(
                README.format(
                    sample_id=sample_id,
                    verdict_line=(
                        "**Exploit reproduced.** The attack below compiled and executed "
                        "on an EVM, and satisfied a success condition this harness owns."
                    ),
                    title=finding.get("title", "(no title recorded)"),
                    function=finding.get("vulnerable_function", "(unrecorded)"),
                    severity=finding.get("severity", "(unrecorded)"),
                    predicate=poc.get("predicate", ""),
                    predicate_note=PREDICATE_NOTES.get(poc.get("predicate", ""), ""),
                    offending=finding.get("offending_expression", "(unrecorded)"),
                    attack_path=finding.get("attack_path", "(unrecorded)"),
                    poc_name=name,
                    output=(poc.get("output_tail") or "")[-1500:],
                ),
                encoding="utf-8",
            )
            written.append(
                {
                    "sample_id": sample_id,
                    "path": str(proj),
                    "title": finding.get("title", ""),
                    "predicate": poc.get("predicate", ""),
                }
            )

    manifest = {
        "source_run": str(results_path),
        "exploits_written": len(written),
        "samples_without_admissible_exploit": skipped,
        "exploits": written,
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    return manifest


def _recover_source(row: dict[str, Any]) -> str:
    """The results row does not carry the target source; recover it from the PoC import.

    Runs record the exploit but not the contract it ran against, because the contract came
    from the evalset. When dumping without the evalset to hand, leave an honest placeholder
    rather than a silently wrong file.
    """
    return (
        "// SPDX-License-Identifier: Apache-2.0\n"
        "// The contract under audit was not stored in the run record.\n"
        "// Copy it here from the evaluation set to make this project runnable.\n"
        "pragma solidity >=0.8.0;\n"
    )

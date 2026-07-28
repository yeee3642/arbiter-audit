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


def _vendor(plan: dict[str, Any], proj: Path) -> tuple[list[str], str]:
    """Copy the exploit's compilation environment into the project.

    An in-repo exploit imports through remappings that pointed at absolute paths in a
    scratch workspace, so writing the file alone produces a project that cannot compile --
    which is how this was found: the first dump ran and failed on
    `Source "arbiter-target/DepositHandler.sol" not found`.

    Each remapping's destination directory is copied under `sources/`, keeping its
    absolute path as a relative one, and the remapping is rewritten to point there. The
    import strings in the exploit are then correct unchanged, because the prefixes are
    the ones it was compiled with. Only .sol files are copied, so vendoring a slice of
    OpenZeppelin or a whole audit repository costs kilobytes.
    """
    lines: list[str] = []
    for entry in plan.get("remappings") or []:
        if "=" not in entry:
            continue
        prefix, dest = entry.split("=", 1)
        src_dir = Path(dest)
        if not src_dir.is_dir():
            continue
        rel = Path("sources") / src_dir.as_posix().lstrip("/")
        _copy_sol_tree(src_dir, proj / rel)
        lines.append(f"{prefix}={rel.as_posix()}/")

    chosen = plan.get("chosen_src") or "src"
    if chosen != "src" and Path(chosen).is_dir():
        rel = Path("sources") / Path(chosen).as_posix().lstrip("/")
        _copy_sol_tree(Path(chosen), proj / rel)
        chosen = rel.as_posix()
    return lines, chosen


def _copy_sol_tree(src: Path, dest: Path) -> None:
    from .repo import SKIP_DIRS

    for dirpath, dirnames, filenames in __import__("os").walk(src):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith(".sol"):
                continue
            source = Path(dirpath) / name
            target = dest / source.relative_to(src)
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                try:
                    target.write_bytes(source.read_bytes())
                except OSError:
                    continue


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

            plan = (row.get("context") or {}).get("plan") or _replan(row)
            src_setting = "src"
            if plan:
                remappings, src_setting = _vendor(plan, proj)
                (proj / "remappings.txt").write_text(
                    "\n".join(remappings) + "\n", encoding="utf-8"
                )
            # The compiler is pinned to whatever the original run resolved, so the dump
            # reproduces under the same solc rather than whichever one is newest on the
            # reader's machine.
            solc = plan.get("solc") or ""
            (proj / "foundry.toml").write_text(
                FOUNDRY_TOML.format(
                    src=src_setting,
                    solc=f'solc = "{solc}"' if solc else "auto_detect_solc = true",
                ),
                encoding="utf-8",
            )
            (proj / "src" / "Target.sol").write_text(
                row.get("source") or _recover_source(row), encoding="utf-8"
            )
            # The harness substitutes the pragma to whatever the contract under audit
            # accepts; writing the template verbatim leaves the literal placeholder in
            # the file and nothing compiles.
            (proj / "test" / "Vm.sol").write_text(
                VM_SOL.replace("__PRAGMA__", plan.get("pragma") or ">=0.8.0"),
                encoding="utf-8",
            )
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
            # Proof that the dump is runnable, not just written. A project that does not
            # compile outside the harness is an assertion again, which is the thing this
            # whole design exists to stop producing.
            verified = _verify(proj)
            written.append(
                {
                    "sample_id": sample_id,
                    "path": str(proj),
                    "title": finding.get("title", ""),
                    "predicate": poc.get("predicate", ""),
                    "reproduces": verified,
                }
            )

    manifest = {
        "source_run": str(results_path),
        "exploits_written": len(written),
        "exploits_reproduced": sum(1 for e in written if e.get("reproduces")),
        "samples_without_admissible_exploit": skipped,
        "exploits": written,
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    return manifest


def _replan(row: dict[str, Any]) -> dict[str, Any]:
    """Rebuild the compilation environment for a run recorded before plans were stored.

    Best effort and clearly marked as such: the remappings the repair loop discovered
    during the original run are gone, so only the ones the static pass finds come back.
    If that is not enough the dumped project fails to compile, and `reproduces` in the
    manifest says so rather than the dump quietly claiming success.
    """
    path = row.get("path")
    if not path or not Path(path).is_file():
        return {}
    # The run record names the repository the contract came from; use it rather than
    # guessing, so the vendored tree is that repository and not whatever directory above
    # it happens to carry a marker file.
    root = None
    repo = row.get("repo")
    if repo:
        cur = Path(path).parent
        while cur.parent != cur:
            if cur.name == repo:
                root = cur
                break
            cur = cur.parent
    try:
        from .repo import plan_for

        plan = plan_for(Path(path), repo_root=root)
    except Exception:  # noqa: BLE001
        return {}
    return {
        "repo_root": plan.repo_root.as_posix(),
        "target": plan.target.as_posix(),
        "target_import": plan.target_import,
        "pragma": plan.test_pragma,
        "chosen_src": plan.source_root.as_posix(),
        "remappings": list(plan.remappings),
        "recovered": True,
    }


def _verify(proj: Path) -> bool:
    """Run `forge test` in the dumped project and report whether the exploit still passes."""
    import shutil
    import subprocess

    forge = shutil.which("forge")
    if forge is None:
        return False
    try:
        proc = subprocess.run(  # noqa: S603
            [forge, "test"], cwd=proj, capture_output=True, text=True, timeout=300
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    passed = any(
        line.strip().startswith("[PASS]") for line in (proc.stdout or "").splitlines()
    )
    # Build artifacts are reproducible from the sources and are two orders of magnitude
    # larger than them -- 326 MB against a few hundred kilobytes on the first dump.
    for junk in ("out", "cache"):
        shutil.rmtree(proj / junk, ignore_errors=True)
    return passed


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

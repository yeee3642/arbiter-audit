"""Which files in a repository are worth spending an audit on.

A checkout is mostly not attack surface. Of the 975 Solidity files in the 17 repositories
OneSavie's evaluation draws from, a large share are interfaces, pure type libraries,
mocks and deployment scripts -- files with no state to corrupt and no value to steal.
Auditing them is not merely wasteful, it is the dominant cost: the gateway rations
requests, not tokens, and in a pilot run the first three files reached were a test ERC20,
a casting library and a struct-definition library. Fifty-two requests bought three
correct but uninteresting "safe" verdicts.

Bastet walks every file too, and stops at the first detector that fires. That is cheap
for it because a fired detector is not checked. It is not cheap here, because evidence
costs execution.

The rule is deliberately mechanical and conservative. It is a *cost* filter, not a
verdict: everything it drops is recorded and counted, and a file is only dropped when it
has no code that could be attacked at all -- no contract to deploy, or nothing but views.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# `contract X` -- an interface or a library is not deployable attack surface on its own.
CONTRACT_RE = re.compile(r"^\s*(?:abstract\s+)?contract\s+(\w+)", re.MULTILINE)
INTERFACE_RE = re.compile(r"^\s*interface\s+(\w+)", re.MULTILINE)
LIBRARY_RE = re.compile(r"^\s*library\s+(\w+)", re.MULTILINE)
ABSTRACT_RE = re.compile(r"^\s*abstract\s+contract\s+(\w+)", re.MULTILINE)

# A function that can change state and that an outsider can reach. `view`/`pure` cannot
# be the vulnerability; `internal`/`private` cannot be called by an attacker directly.
FUNCTION_RE = re.compile(
    r"function\s+(\w+)\s*\([^)]*\)\s*((?:[\w\s()]|,)*?)(?:returns|\{|;)", re.DOTALL
)

# Paths that are, by the project's own convention, not the thing being shipped.
NONPRODUCTION_RE = re.compile(
    r"(^|/)(test|tests|mock|mocks|mocking|script|scripts|deploy|echidna|fuzz|"
    r"invariant|helpers?|examples?)(/|$)",
    re.IGNORECASE,
)


@dataclass
class Triage:
    path: Path
    audit: bool
    reason: str
    contracts: list[str]
    state_changing: list[str]

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path.as_posix(),
            "audit": self.audit,
            "reason": self.reason,
            "contracts": self.contracts,
            "state_changing": self.state_changing[:12],
        }


def state_changing_externals(source: str) -> list[str]:
    """Externally reachable functions that are not view or pure."""
    out: list[str] = []
    for match in FUNCTION_RE.finditer(source):
        name, mods = match.group(1), match.group(2) or ""
        if re.search(r"\b(view|pure)\b", mods):
            continue
        if not re.search(r"\b(external|public)\b", mods):
            continue
        out.append(name)
    return out


def triage_file(path: Path, source: str | None = None) -> Triage:
    text = source if source is not None else path.read_text(
        encoding="utf-8", errors="ignore"
    )
    concrete = [
        name
        for name in CONTRACT_RE.findall(text)
        if name not in ABSTRACT_RE.findall(text)
    ]
    externals = state_changing_externals(text)

    if not concrete:
        kind = (
            "interface" if INTERFACE_RE.search(text)
            else "library" if LIBRARY_RE.search(text)
            else "abstract" if ABSTRACT_RE.search(text)
            else "no contract"
        )
        return Triage(path, False, f"declares no deployable contract ({kind})",
                      concrete, externals)

    if not externals:
        return Triage(path, False, "no externally reachable state-changing function",
                      concrete, externals)

    if NONPRODUCTION_RE.search(path.as_posix()):
        return Triage(path, False, "path is test, mock or deployment scaffolding",
                      concrete, externals)

    return Triage(path, True, f"{len(concrete)} contract(s), {len(externals)} "
                              "state-changing entry point(s)", concrete, externals)


def triage_all(paths: list[Path]) -> tuple[list[Triage], list[Triage]]:
    """Split into (worth auditing, skipped). Both are returned; neither is discarded."""
    keep: list[Triage] = []
    drop: list[Triage] = []
    for path in paths:
        try:
            result = triage_file(path)
        except OSError as exc:  # unreadable file is not attack surface we can reach
            result = Triage(path, False, f"unreadable: {exc}", [], [])
        (keep if result.audit else drop).append(result)
    return keep, drop

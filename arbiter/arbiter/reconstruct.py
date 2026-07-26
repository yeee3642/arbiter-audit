"""Restore the compilation context that snippet extraction stripped.

Ten of the fourteen evaluation samples do not compile. They are not contracts, they are
fragments cut out of real repositories: `V3` references `DoubleEndedQueue`,
`STAKE_HUB_ADDR`, `IStakeHub`, `_burnAndSync` and six custom errors that were never
carried across with it. Nothing can execute against them, which is fatal for any method
that proves findings by running them.

The obvious repair -- rewrite the samples until they compile -- would quietly make us
the author of the code the vulnerabilities live in, and a reviewer would be right to
discount every number that followed. So the repair is constrained until it is no longer
a rewrite:

  1. The model may only ADD declarations: interfaces, base contracts, libraries,
     constants, custom errors, modifiers and helper function bodies. It is told not to
     touch a single existing line.
  2. That is then enforced rather than requested. Every non-trivial line of the original
     sample must still be present, verbatim, in the reconstructed file. If one is
     missing the attempt is rejected and retried. `verify_preserved` is the gate.
  3. A vulnerable sample and its patched partner are reconstructed TOGETHER and receive
     one identical prelude, so the only difference between the pair remains the fix.
     This is what keeps the paired negatives meaningful: if the two halves got different
     scaffolding, a system could separate them on the scaffolding instead of the bug.
  4. The compiler is the acceptance test, and it runs on both halves.

What this still cannot do is prove the reconstruction preserved *semantics*. A stub for
`_burnAndSync` is our stub, not BNB Chain's. That is recorded honestly in the evalset
metadata, and it is the reason results are reported separately for reconstructed and
natively-compiling samples.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .gateway import Gateway
from .workspace import Workspace

MAX_ATTEMPTS = 5

SYSTEM = """\
You restore missing declarations so that an extracted Solidity fragment compiles again.

You are given one or two Solidity sources that were cut out of a larger repository. The \
extraction left behind references to types, constants, errors, modifiers and helper \
functions that no longer exist, so the code does not compile.

Your job is to write a PRELUDE: the missing declarations, and nothing else. The prelude \
will be placed above the original source, unchanged, and the result must compile.

Absolute rules:

- You MUST NOT modify, reorder, reformat or delete any line of the original source. It \
is appended after your prelude exactly as given. This is checked mechanically and a \
violation is rejected.
- You MUST NOT change the behaviour of the code under audit. Write faithful \
declarations, not convenient ones. If a modifier is named `nonReentrant`, implement a \
real reentrancy lock. If a function is named `_burnAndSync`, implement something that \
plausibly burns and returns an amount. Do not turn a guard into a no-op and do not add \
a guard that was not there.
- If both a vulnerable and a patched version are given, produce ONE prelude that makes \
BOTH compile. They differ only by a security fix and must keep differing only by that.
- Declare only what is missing. Do not restate anything the source already declares.
- Do not include a `pragma` line and do not include the original source in your answer.

Reply with ONLY Solidity source for the prelude. No prose, no markdown fences.\
"""

USER_TEMPLATE = """\
{sources}

The compiler currently rejects this with:

{errors}

Write the prelude that makes it compile.\
"""

RETRY_TEMPLATE = """\
Your prelude did not work. Here is what you produced:

```solidity
{prelude}
```

Compiling `prelude + original source` gives:

{errors}

Fix the prelude and reply with the corrected prelude only.\
"""


@dataclass
class Reconstruction:
    ok: bool
    prelude: str
    sources: dict[str, str]
    attempts: int
    error: str = ""
    preserved: bool = True


def strip_fences(text: str) -> str:
    text = re.sub(r"^```(?:solidity|sol)?\s*", "", text.strip(), flags=re.M)
    return re.sub(r"```\s*$", "", text, flags=re.M).strip()


def split_pragma(source: str) -> tuple[str, str]:
    """Separate a leading pragma so the prelude can sit under it."""
    match = re.search(r"^\s*pragma solidity[^;]*;\s*$", source, flags=re.M)
    if not match:
        return "", source
    return source[match.start() : match.end()].strip(), (
        source[: match.start()] + source[match.end() :]
    )


def significant_lines(source: str) -> list[str]:
    """Lines that must survive reconstruction.

    Braces, blank lines and pragmas are excluded because they legitimately move; every
    other line carries semantics and must appear verbatim in the output.
    """
    out = []
    for raw in source.splitlines():
        line = raw.strip()
        if not line or line in {"}", "{", "});"}:
            continue
        if line.startswith("pragma") or line.startswith("//"):
            continue
        out.append(line)
    return out


def verify_preserved(original: str, rebuilt: str) -> tuple[bool, list[str]]:
    """Every significant line of the original must appear verbatim in the rebuilt file."""
    squash = lambda s: re.sub(r"\s+", " ", s).strip()  # noqa: E731
    haystack = squash(rebuilt)
    missing = [line for line in significant_lines(original) if squash(line) not in haystack]
    return (not missing), missing


def assemble(prelude: str, source: str) -> str:
    pragma, body = split_pragma(source)
    parts = [pragma] if pragma else []
    parts.append("\n// ---- reconstructed compilation context (added, nothing removed) ----")
    parts.append(strip_fences(prelude))
    parts.append("// ---- original extracted source, verbatim ----")
    parts.append(body.strip())
    return "\n".join(parts) + "\n"


def reconstruct_group(
    gateway: Gateway,
    group: list[dict[str, Any]],
    workspace_root: Path,
    max_tokens: int = 8192,
) -> Reconstruction:
    """Reconstruct one sample, or one vulnerable/patched pair sharing a prelude."""

    def compile_all(prelude: str) -> tuple[bool, str, dict[str, str]]:
        sources = {item["id"]: assemble(prelude, item["code"]) for item in group}
        errors: list[str] = []
        for sample_id, src in sources.items():
            ws = Workspace(workspace_root, f"recon_{sample_id}", src)
            result = ws.build()
            ws.cleanup()
            if not result.ok:
                head = "\n".join(
                    line
                    for line in result.combined.splitlines()
                    if line.strip().startswith(("Error", "-->", "  |"))
                )[:2500]
                errors.append(f"--- {sample_id} ---\n{head or result.combined[-1500:]}")
        return (not errors), "\n\n".join(errors), sources

    ok, errors, _ = compile_all("")
    if ok:
        return Reconstruction(
            True, "", {i["id"]: i["code"] for i in group}, 0, preserved=True
        )

    listing = "\n\n".join(
        f"=== {item['id']} ({'vulnerable' if item['label'] == 'vuln' else 'patched'}) ==="
        f"\n```solidity\n{item['code']}\n```"
        for item in group
    )
    messages = [
        {"role": "system", "content": SYSTEM},
        {
            "role": "user",
            "content": USER_TEMPLATE.format(sources=listing, errors=errors[:6000]),
        },
    ]

    prelude = ""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        reply = gateway.chat(
            messages,
            max_tokens=max_tokens,
            temperature=0.0,
            tag=f"reconstruct:{group[0]['id']}:a{attempt}",
        )
        prelude = strip_fences(reply.get("content") or "")
        if not prelude:
            messages.append({"role": "assistant", "content": ""})
            messages.append(
                {"role": "user", "content": "Empty reply. Send the prelude Solidity only."}
            )
            continue

        ok, errors, sources = compile_all(prelude)
        if ok:
            for item in group:
                preserved, missing = verify_preserved(item["code"], sources[item["id"]])
                if not preserved:
                    return Reconstruction(
                        False,
                        prelude,
                        sources,
                        attempt,
                        error=(
                            f"{item['id']}: reconstruction dropped or altered "
                            f"{len(missing)} original line(s), first: {missing[0][:120]!r}"
                        ),
                        preserved=False,
                    )
            return Reconstruction(True, prelude, sources, attempt)

        messages.append({"role": "assistant", "content": prelude})
        messages.append(
            {
                "role": "user",
                "content": RETRY_TEMPLATE.format(
                    prelude=prelude[:4000], errors=errors[:6000]
                ),
            }
        )

    return Reconstruction(
        False, prelude, {}, MAX_ATTEMPTS, error=f"did not compile in {MAX_ATTEMPTS} attempts"
    )


# Which samples share a prelude. Taken from the evaluation set's own metadata rather
# than guessed from the identifiers: S1..S4 are the remediated versions of V1..V4, but
# S5 is un-flagged production code from the *same contract as V7*, not from V5. V5, V6,
# S6 and S7 have no partner and are reconstructed alone.
PAIRS: dict[str, str] = {
    "V1_reentrancy_withdraw": "pair_reentrancy",
    "S1_reentrancy_withdraw_fixed": "pair_reentrancy",
    "V2_phantom_balance_buyback": "pair_phantom",
    "S2_phantom_balance_buyback_fixed": "pair_phantom",
    "V3_stakecredit_slash_evasion": "pair_stakecredit",
    "S3_stakecredit_slash_fixed": "pair_stakecredit",
    "V4_slippage_branch_bypass": "pair_slippage",
    "S4_slippage_branch_fixed": "pair_slippage",
    "V7_rwavault_convert_owner_rug": "pair_rwavault",
    "S5_rwavault_redeem_hardened": "pair_rwavault",
}


def pair_key(sample_id: str) -> str:
    """Group a vulnerable sample with its patched partner, if it has one."""
    return PAIRS.get(sample_id, sample_id)

"""Admission control for the paired benchmark.

A benchmark whose samples nobody checked is a liability, not an asset. Every pair here
has to earn its place by passing a test no language model is involved in:

    the reference exploit must PASS against the vulnerable half
    the same exploit must FAIL against the patched half

Both halves must also compile. A pair that fails any of those four checks is rejected
and never reaches a scoring run, which means the benchmark cannot contain a "vulnerable"
sample that is not exploitable or a "patched" sample that is still broken -- the two ways
a hand-built benchmark usually rots.

The exploit runs through exactly the same `compose_exploit` harness the auditor agent is
held to, so the reference exploit and an agent's exploit are judged by one predicate.
That matters: it means the benchmark's own ground truth and the system under test are
measured with the same instrument, and a bug in the instrument shows up as an admission
failure here rather than as a silent scoring error later.

What this does NOT establish is that the vulnerable half is exploitable *only* in the
intended way, or that the patched half is secure in general. It establishes that the pair
is a controlled instrument for the one attack it was built around, which is what a paired
comparison needs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .tools import _test_passed
from .workspace import Workspace


@dataclass
class PairVerdict:
    slug: str
    admitted: bool
    vuln_compiles: bool = False
    patched_compiles: bool = False
    exploit_passes_on_vuln: bool = False
    exploit_fails_on_patched: bool = False
    only_differs_by_fix: bool = True
    diff_lines: int = 0
    reasons: list[str] = field(default_factory=list)
    detail: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "admitted": self.admitted,
            "vuln_compiles": self.vuln_compiles,
            "patched_compiles": self.patched_compiles,
            "exploit_passes_on_vuln": self.exploit_passes_on_vuln,
            "exploit_fails_on_patched": self.exploit_fails_on_patched,
            "diff_lines": self.diff_lines,
            "reasons": self.reasons,
        }


def diff_line_count(a: str, b: str) -> int:
    """How many lines differ between the halves, ignoring whitespace.

    Reported rather than enforced. A guard is sometimes one line and sometimes five
    (a modifier plus its state variable plus its application), so there is no honest
    threshold; but a pair whose halves differ by forty lines is not a controlled pair
    and the number makes that visible.
    """
    import difflib

    left = [ln.strip() for ln in a.splitlines() if ln.strip()]
    right = [ln.strip() for ln in b.splitlines() if ln.strip()]
    diff = difflib.unified_diff(left, right, lineterm="", n=0)
    return sum(1 for line in diff if line.startswith(("+", "-")) and not line.startswith(("+++", "---")))


def verify_pair(
    pair: dict[str, Any], workspace_root: Path, keep_failed: bool = False
) -> PairVerdict:
    """Run the four admission checks on one pair."""
    slug = pair["slug"]
    verdict = PairVerdict(slug=slug, admitted=False)
    predicate = pair.get("predicate", "eth_profit")
    getter = pair.get("observed_getter", "") or ""

    verdict.diff_lines = diff_line_count(pair["vulnerable_code"], pair["patched_code"])
    if pair["vulnerable_code"].strip() == pair["patched_code"].strip():
        verdict.reasons.append("halves are identical; there is no fix")
        return verdict

    for half, code, want_pass in (
        ("vuln", pair["vulnerable_code"], True),
        ("patched", pair["patched_code"], False),
    ):
        ws = Workspace(workspace_root, f"bench_{slug}_{half}", code)
        build = ws.build()
        if half == "vuln":
            verdict.vuln_compiles = build.ok
        else:
            verdict.patched_compiles = build.ok
        if not build.ok:
            verdict.reasons.append(
                f"{half} half does not compile: "
                + _first_error(build.combined)
            )
            verdict.detail[f"{half}_build"] = build.combined[-1500:]
            if not keep_failed:
                ws.cleanup()
            continue

        try:
            solidity = ws.compose_exploit(
                deploy_code=pair["deploy_code"],
                attacker_code=pair["attacker_code"],
                predicate=predicate,
                observed_getter=getter,
                token_expr=pair.get("token_expr", "") or "",
                liveness_call=pair.get("liveness_call", "") or "",
                attack_body=pair.get("attack_body", "") or "",
                honest_body=pair.get("honest_body", "") or "{}",
                mode=pair.get("mode", "contract") or "contract",
                require_honest=False,
            )
        except ValueError as exc:
            verdict.reasons.append(f"{half}: bad exploit spec: {exc}")
            ws.cleanup()
            continue

        name = ws.write_poc("Ref", solidity)
        exploit_build = ws.build()
        if not exploit_build.ok:
            verdict.reasons.append(
                f"{half}: reference exploit does not compile: "
                + _first_error(exploit_build.combined)
            )
            verdict.detail[f"{half}_exploit_build"] = exploit_build.combined[-1500:]
            ws.cleanup()
            continue

        run = ws.run_poc(name)
        passed = _test_passed(run)
        if half == "vuln":
            verdict.exploit_passes_on_vuln = passed
            if not passed:
                verdict.reasons.append(
                    "reference exploit FAILED on the vulnerable half, so the sample is "
                    "not demonstrably exploitable: " + _first_failure(run.combined)
                )
                verdict.detail["vuln_run"] = run.combined[-1500:]
        else:
            verdict.exploit_fails_on_patched = not passed
            if passed:
                verdict.reasons.append(
                    "reference exploit PASSED on the patched half, so the fix does not "
                    "actually resist the attack"
                )
                verdict.detail["patched_run"] = run.combined[-1500:]
        ws.cleanup()

    verdict.admitted = (
        verdict.vuln_compiles
        and verdict.patched_compiles
        and verdict.exploit_passes_on_vuln
        and verdict.exploit_fails_on_patched
    )
    return verdict


def build_evalset(
    pairs: list[dict[str, Any]],
    workspace_root: Path,
    out_path: Path,
    source_note: str = "",
) -> dict[str, Any]:
    """Verify every pair and emit an evalset containing only the admitted ones."""
    verdicts = []
    items = []
    for pair in pairs:
        verdict = verify_pair(pair, workspace_root)
        verdicts.append(verdict)
        mark = "ADMIT " if verdict.admitted else "REJECT"
        print(
            f"[{mark}] {pair['slug'][:38]:40s} "
            f"compile={int(verdict.vuln_compiles)}{int(verdict.patched_compiles)} "
            f"exploit={int(verdict.exploit_passes_on_vuln)}"
            f"{int(verdict.exploit_fails_on_patched)} "
            f"diff={verdict.diff_lines}",
            flush=True,
        )
        for reason in verdict.reasons:
            print(f"         {reason[:150]}", flush=True)
        if not verdict.admitted:
            continue
        items.append(
            {
                "id": f"V_{pair['slug']}",
                "label": "vuln",
                "true_tag": pair.get("vulnerability_class", ""),
                "code": pair["vulnerable_code"],
                "pair": pair["slug"],
                "notes": pair.get("the_fix", ""),
            }
        )
        items.append(
            {
                "id": f"S_{pair['slug']}",
                "label": "safe",
                "true_tag": "-",
                "code": pair["patched_code"],
                "pair": pair["slug"],
                "notes": pair.get("why_patched_resists", ""),
            }
        )

    meta = {
        "n": len(items),
        "n_vuln": sum(1 for i in items if i["label"] == "vuln"),
        "n_safe": sum(1 for i in items if i["label"] == "safe"),
        "pairs_admitted": sum(1 for v in verdicts if v.admitted),
        "pairs_offered": len(verdicts),
        "source": source_note,
        "admission_rule": (
            "A pair enters only if both halves compile, the reference exploit PASSES "
            "against the vulnerable half under the harness-owned predicate, and the "
            "SAME exploit FAILS against the patched half. No model adjudicates this."
        ),
        "negative_design": (
            "Every negative is the patched version of a positive, differing only by the "
            "security fix. Unrelated safe code as a negative would inflate precision for "
            "both arms and destroy the discriminative power of the comparison."
        ),
        "comment_policy": (
            "Comments that would reveal the label are stripped, and the halves carry "
            "identical comment text."
        ),
        "verdicts": [v.as_dict() for v in verdicts],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps({"meta": meta, "items": items}, ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    return meta


def _first_error(text: str) -> str:
    for line in text.splitlines():
        if line.strip().startswith("Error"):
            return line.strip()[:160]
    return text.strip().splitlines()[-1][:160] if text.strip() else "(no output)"


def _first_failure(text: str) -> str:
    for line in text.splitlines():
        if "[FAIL" in line:
            return line.strip()[:160]
    return "(no [FAIL] line)"

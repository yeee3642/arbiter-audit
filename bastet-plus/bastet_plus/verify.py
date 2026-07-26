"""Stage 2: adversarial verification.

The original harness was single-stage: one prompt, one call, whatever came back
went straight into the report. A detector prompt is inherently biased toward
finding its own bug class -- you have just told the model "you are looking for
missing slippage protection", so it finds missing slippage protection, including
where a `require(out >= minOut)` sits three lines below.

Here each surviving candidate is re-examined by a fresh call that is framed to
*refute*, is given the code but not the detector's leading question, and is told
the reporter is unreliable. Asymmetric framing matters: a verifier prompted
neutrally agrees with the claim it is shown roughly nine times out of ten.
"""

from __future__ import annotations

from .llm import LLMClient
from .schema import VERDICT_SCHEMA, Finding

_SYSTEM = (
    "You are a senior smart-contract auditor doing final triage before a report ships to a "
    "client. An automated scanner produced the candidate below. Scanners over-report badly: "
    "most candidates you see are false positives, usually because the scanner missed a check "
    "that exists elsewhere in the code, or flagged a pattern that is not actually exploitable "
    "in this contract.\n\n"
    "Your job is to REJECT unless the code in front of you proves the bug is real.\n\n"
    "Reject when:\n"
    "  - the protection the scanner says is missing is in fact present anywhere in the shown code\n"
    "  - the quoted snippet does not appear in the source, or has been paraphrased\n"
    "  - the function is unreachable, or restricted to a trusted role, and that is the intended design\n"
    "  - exploiting it requires an assumption not supported by the code (an unstated malicious token, "
    "a privileged actor already compromised, a caller that cannot exist)\n"
    "  - it is a style, gas, or naming observation with no security impact\n"
    "  - the claim describes correct, idiomatic behaviour\n\n"
    "Confirm only when you can state the concrete exploit path: who calls what, in what order, "
    "and what they gain. If you cannot state that path, set is_real to false.\n\n"
    "Answer with the JSON object only."
)


def _numbered(text: str, start_line: int = 1) -> str:
    return "\n".join(f"{i:>5} | {ln}" for i, ln in enumerate(text.splitlines(), start_line))


def _user_prompt(f: Finding, source: str, start_line: int) -> str:
    ev = "\n".join(f.code_snippet) if f.code_snippet else "(the scanner quoted no code)"
    grounded_note = (
        "The harness verified this snippet appears verbatim in the source."
        if f.grounded else
        "WARNING: the harness could NOT find this snippet in the source. Treat the claim as suspect."
    )
    return (
        "## Source under review\n\n```solidity\n" + _numbered(source, start_line) + "\n```\n\n"
        "## Candidate finding\n\n"
        f"- claimed function: `{f.function_name}`\n"
        f"- claimed severity: {f.severity}\n"
        f"- summary: {f.summary}\n"
        f"- reasoning given: {f.description}\n"
        f"- quoted evidence:\n```solidity\n{ev}\n```\n"
        f"- evidence check: {grounded_note}\n\n"
        "## Your task\n\n"
        "Decide whether this is a genuine, exploitable vulnerability in the code above. "
        "State the exploit path in `reason` if you confirm it, or the specific line that "
        "refutes it if you reject it."
    )


def verify_one(client: LLMClient, f: Finding, source: str, start_line: int = 1,
               votes: int = 1, model: str | None = None) -> tuple[bool, Finding]:
    """Run the refutation panel on one finding. Returns ``(survived, finding)``."""
    messages = [{"role": "system", "content": _SYSTEM},
                {"role": "user", "content": _user_prompt(f, source, start_line)}]

    confirms, reasons, severities, confidences = 0, [], [], []
    for i in range(max(1, votes)):
        verdict = client.complete_json(
            messages, VERDICT_SCHEMA, model=model,
            temperature=0.0 if votes == 1 else 0.4,
            # Vary the seed per juror, otherwise a deterministic backend returns
            # the same answer k times and the "panel" is theatre.
            seed=None if votes == 1 else 1000 + i,
            max_tokens=700, schema_name="verdict",
        )
        if not isinstance(verdict, dict):
            continue
        if bool(verdict.get("is_real")):
            confirms += 1
            severities.append(str(verdict.get("severity", f.severity)).lower())
        reasons.append(str(verdict.get("reason", ""))[:400])
        try:
            confidences.append(float(verdict.get("confidence", 0.5)))
        except (TypeError, ValueError):
            pass

    need = (max(1, votes) // 2) + 1
    survived = confirms >= need
    f.verdict_reason = (reasons[0] if reasons else "verifier produced no parsable verdict")
    if confidences:
        # Blend detector and verifier confidence; the verifier gets more weight.
        f.confidence = round(0.35 * f.confidence + 0.65 * (sum(confidences) / len(confidences)), 3)
    if survived and severities:
        counts: dict[str, int] = {}
        for s in severities:
            if s in ("high", "medium", "low"):
                counts[s] = counts.get(s, 0) + 1
        if counts:
            order = {"low": 0, "medium": 1, "high": 2}
            f.severity = max(counts, key=lambda s: (counts[s], order[s]))
    if not survived:
        f.verdict_reason = f"rejected by verifier ({confirms}/{max(1, votes)} confirmed): " + f.verdict_reason
    return survived, f

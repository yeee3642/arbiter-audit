"""Deterministic markdown assembly: S2 JSON in, appendix-A detector file out.

The model never writes markdown. Frontmatter is emitted here with json.dumps for
every list/mapping value (JSON is valid YAML flow syntax), so a synthesized file
can never break the detector loader no matter what the model produced. Filename
== frontmatter id is a hard invariant: prompts.detection_prompt resolves
`<id>.md` by name.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import DETECTORS_SYNTH_DIR

UPSTREAM_MODEL = "ais3/nemotron-3-ultra-550b"

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slug(tag: str) -> str:
    return _SLUG_RE.sub("_", tag.lower()).strip("_")


def detector_id(tag: str) -> str:
    return f"synth__{slug(tag)}"


def render_body(name: str, det: dict) -> str:
    """The '## Detection prompt' section body, mirroring the hand-written
    detectors' structure (Knowledge -> Checks -> Examples -> Task -> Output)."""
    lines = [
        "You are a smart contract auditor. After reading the following "
        "vulnerability knowledge and detection checks, examine the contract code "
        "for this specific class of issue.",
        "",
        "### Vulnerability Knowledge",
        "",
        f"**{name}**",
        det["vulnerability_knowledge"],
        "",
        "### Detection Checks",
        "",
    ]
    for i, check in enumerate(det["checks"], 1):
        lines.append(f"{i}. {check}")
    inc, cor = det.get("incorrect_example") or {}, det.get("correct_example") or {}
    if (inc.get("code") or "").strip():
        lines += [
            "", "### Examples", "",
            "#### Example 1: Incorrect Example", "",
            "```solidity", inc["code"].strip("\n"), "```", "",
            inc.get("explanation", ""),
        ]
        if (cor.get("code") or "").strip():
            lines += [
                "", "#### Example 2: Correct Example", "",
                "```solidity", cor["code"].strip("\n"), "```", "",
                cor.get("explanation", ""),
            ]
    lines += [
        "", "### Task to Perform",
        "Apply each detection check above to every contract function provided. "
        "Report only concrete instances of this vulnerability class, citing the "
        "specific check that failed and the offending lines.",
        "", "### Output Format",
        "If NO concrete vulnerability found, output a empty array",
    ]
    return "\n".join(lines)


def render_markdown(tag: str, det: dict, routing_hints: list[str],
                    required_hints: list[str], gated: bool,
                    provenance: dict) -> tuple[str, str, int]:
    """(detector_id, full markdown, prompt_chars) for one synthesized detector."""
    did = detector_id(tag)
    name = det.get("name") or tag
    body = render_body(name, det)
    prompt_chars = len(body)
    front = "\n".join([
        "---",
        f"id: {did}",
        f"name: {json.dumps(name)}",
        "source_workflow: synthesized",
        f"upstream_model: {UPSTREAM_MODEL}",
        f"tags: {json.dumps([tag])}",
        f"routing_hints: {json.dumps(routing_hints)}",
        f"required_hints: {json.dumps(required_hints)}",
        f"prompt_chars: {prompt_chars}",
        "synthesized: true",
        f"gated: {'true' if gated else 'false'}",
        f"synth_provenance: {json.dumps(provenance)}",
        "---",
    ])
    md = f"{front}\n\n# {name}\n\n## Detection prompt\n\n{body}\n"
    return did, md, prompt_chars


def assemble_all(final_records: list[dict],
                 out_dir: Path = DETECTORS_SYNTH_DIR) -> list[dict]:
    """Write every detector md plus index.json; returns the index entries.

    final_records: [{tag, detector, routing_hints, required_hints, gated,
    provenance}]. Index entries carry the three new Detector fields (DESIGN §1.2);
    routing.load_detectors needs the appendix-B field additions to read them.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    index: list[dict] = []
    for rec in final_records:
        did, md, prompt_chars = render_markdown(
            rec["tag"], rec["detector"], rec["routing_hints"],
            rec["required_hints"], rec["gated"], rec["provenance"])
        (out_dir / f"{did}.md").write_text(md)
        index.append({
            "id": did,
            "name": rec["detector"].get("name") or rec["tag"],
            "source_workflow": "synthesized",
            "tags": [rec["tag"]],
            "routing_hints": rec["routing_hints"],
            "prompt_chars": prompt_chars,
            "required_hints": rec["required_hints"],
            "gated": rec["gated"],
            "synthesized": True,
        })
    index.sort(key=lambda d: d["id"])
    (out_dir / "index.json").write_text(json.dumps(index, indent=1))
    return index

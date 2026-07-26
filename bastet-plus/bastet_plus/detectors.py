"""Detector registry.

A *detector* is one vulnerability class plus the prompt that hunts for it. The
originals live inside n8n workflow JSON as ``chainLlm`` nodes; ``tools/extract_prompts.py``
lifts them to ``prompts/legacy/*.md`` so both harnesses can share byte-identical
detection knowledge. That is the whole point: the A/B measures the *harness*,
not the prompts.

The only prompt-side change the enhanced path makes is replacing the trailing
"Output Format" block with the block derived from ``schema.py``. That is
plumbing, not knowledge -- and it is necessary, because 55 of the 56 original
prompts ship an output contract that disagrees with the JSON Schema the
workflow actually enforces (see ``schema.py`` for the full story).
"""

from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass

from .schema import prompt_format_block

# Typographic characters were destroyed somewhere in the workflows' authoring
# pipeline. Two of these lost actual information (numeric literals); the rest
# are recoverable from context. Applied to the enhanced path only.
_MOJIBAKE_FIXES = [
    ("Your output should contain each step? thinking.", "Your output should contain each step's thinking."),
    ("report that function? vulnerability", "report that function's vulnerability"),
    ("If the conclusion of a function is ?o vulnerability?? report with a empty array",
     'If the conclusion of a function is "No vulnerability", report with an empty array'),
    ("didnt clear buy_amt_min??;", 'didnt clear buy_amt_min");'),
    ("return seemingly ?resh??data", 'return seemingly "fresh" data'),
    ("an ?int8??will lead to", 'an "int8" will lead to'),
    ("�", ""),
]

_OUTPUT_HEADER = re.compile(
    r"(?im)^\s*#{1,4}\s*(report format|output format|response format)\s*$.*\Z", re.S | re.M
)


@dataclass
class Detector:
    name: str        # e.g. "slippage__0"
    pack: str        # e.g. "slippage"
    title: str       # human-readable node name from the original workflow
    raw: str         # the original prompt, byte-for-byte (baseline uses this)
    body: str        # detection knowledge with the output-format block stripped

    def legacy_prompt(self) -> str:
        return self.raw

    def enhanced_prompt(self) -> str:
        body = self.body
        for bad, good in _MOJIBAKE_FIXES:
            body = body.replace(bad, good)
        return (
            body.rstrip()
            + "\n\n---\n\n"
            + prompt_format_block()
            + "\n## Discipline\n"
            "- Report ONLY what you can prove from the code you were shown. Do not assume the\n"
            "  existence of code you cannot see.\n"
            "- A defence that is present but implemented elsewhere in the shown context is NOT a\n"
            "  vulnerability. Re-read the contract-level context before reporting.\n"
            "- One entry per distinct vulnerable function. Do not report the same issue twice.\n"
            "- If unsure, set a low `confidence` rather than omitting the finding.\n"
        )


def load_detectors(prompt_dir: str | pathlib.Path, packs: list[str] | None = None,
                   names: list[str] | None = None) -> list[Detector]:
    d = pathlib.Path(prompt_dir)
    out: list[Detector] = []
    for path in sorted(d.glob("*.md")):
        name = path.stem
        pack = name.split("__")[0]
        if packs and pack not in packs:
            continue
        if names and name not in names:
            continue
        raw = path.read_text(encoding="utf-8")
        body = _OUTPUT_HEADER.sub("", raw).rstrip()
        # Some prompts describe the format without a heading; cut at the first
        # bare JSON template block if the heading strip found nothing.
        if body == raw.rstrip():
            body = re.split(r"\n```\s*\n\s*\[\s*\n\s*\{", raw)[0].rstrip()
        out.append(Detector(name=name, pack=pack, title=name, raw=raw, body=body))
    return out


def available_packs(prompt_dir: str | pathlib.Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in pathlib.Path(prompt_dir).glob("*.md"):
        pack = path.stem.split("__")[0]
        counts[pack] = counts.get(pack, 0) + 1
    return dict(sorted(counts.items()))

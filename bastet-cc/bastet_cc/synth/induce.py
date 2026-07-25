"""S2 pattern induction: one LLM call per missing tag, JSON out, markdown never.

The model receives material that is already in code vocabulary -- S1
fault_patterns plus the real vulnerable snippets -- so "induce checks from
descriptions" never actually happens at the prose level. The output is a JSON
detector body; assemble.py renders the markdown deterministically, which is what
guarantees frontmatter validity for every synthesized file.

Tags with fewer than 3 localized triples fall back to S2b: definition text plus
raw descriptions, model-invented examples, and a mandatory `gated` flag downstream.
Temperature is 0.3 (the one sanctioned exception to temp-0, DESIGN §1.6): induction
needs generalization, and the artifact is a frozen file, so scan reproducibility
does not depend on replaying this call.
"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path

from . import SEED, TAG_DEFINITIONS_MD, DETECTORS_DIR

# Style anchors (DESIGN §2.3 S2): one knowledge-heavy, one example-heavy detector.
ANCHOR_IDS = [
    "chainlink__chainlink_not_checking_for_stale_prices",
    "slippage__slippage_no_expiration_deadline",
]

MIN_TRIPLES = 3          # below this, S2b
MAX_TRIPLES = 10
MAX_PER_REPO = 3
SNIPPET_LINES = 80

INDUCE_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "detector": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "vulnerability_knowledge": {"type": "string"},
                "checks": {"type": "array", "items": {"type": "string"}},
                "incorrect_example": {
                    "type": "object",
                    "properties": {"code": {"type": "string"},
                                   "explanation": {"type": "string"}},
                },
                "correct_example": {
                    "type": "object",
                    "properties": {"code": {"type": "string"},
                                   "explanation": {"type": "string"}},
                },
                "routing_hint_candidates": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["name", "vulnerability_knowledge", "checks",
                         "routing_hint_candidates"],
        },
    },
    "required": ["detector"],
}

INDUCE_SYSTEM = (
    "You design vulnerability detectors for a smart contract auditing pipeline. "
    "Given an official vulnerability tag definition and evidence, produce ONE "
    "detector as a single JSON object, no markdown fences, no prose:\n"
    '{"detector": {"name": "", "vulnerability_knowledge": "", '
    '"checks": ["..."], '
    '"incorrect_example": {"code": "", "explanation": ""}, '
    '"correct_example": {"code": "", "explanation": ""}, '
    '"routing_hint_candidates": ["..."]}}\n\n'
    "Requirements:\n"
    "- `vulnerability_knowledge`: 1-3 paragraphs an auditor reads before the code; "
    "concrete mechanisms, not definitions restated.\n"
    "- `checks`: 4 to 8 code-level rules, each independently verifiable by reading "
    "a Solidity function (mention state ordering, missing require/validation, "
    "wrong operand, callback timing, etc.).\n"
    "- `incorrect_example`/`correct_example`: short Solidity snippets (<=25 lines) "
    "showing the flaw and its fix, with one-sentence explanations.\n"
    "- `routing_hint_candidates`: 10 to 30 identifiers that would LITERALLY appear "
    "in vulnerable Solidity source (function names, member accesses like "
    "`msg.sender`, event/type names). Prefer rare, class-specific identifiers over "
    "generic ones like `transfer` or `require`."
)


def parse_tag_definitions(md_path: Path = TAG_DEFINITIONS_MD) -> dict[str, dict]:
    """Canonical tag -> {description, subtags} from the official definitions table."""
    from ..tags import canonical_tag

    out: dict[str, dict] = {}
    in_tag_table = False
    for line in Path(md_path).read_text().splitlines():
        if line.startswith("## "):
            in_tag_table = line.strip() == "## Tag"
            continue
        if line.startswith("### "):
            in_tag_table = False
            continue
        if not in_tag_table or not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 4 or cells[0] in ("Title", ""):
            continue
        if set(cells[0]) <= {"-", " "}:
            continue
        title = canonical_tag(cells[0])
        desc = cells[1].replace("<br>", "\n")
        subtags = [s.strip() for s in cells[3].split(",") if s.strip()]
        out[title] = {"description": desc, "subtags": subtags}
    return out


def anchor_texts(detectors_dir: Path = DETECTORS_DIR) -> list[str]:
    return [(detectors_dir / f"{aid}.md").read_text() for aid in ANCHOR_IDS]


def sample_triples(tag: str, records: list[dict],
                   exclude_repo: str | None = None) -> list[dict]:
    """Stratified pick of localized triples: >=1 per subtag where possible,
    <=3 per repo, <=10 total, deterministic under SEED."""
    pool = [
        r for r in records
        if r["localized"] and tag in r["tags"] and r["repo"] != (exclude_repo or "")
    ]
    rng = random.Random(f"{SEED}|{tag}|{exclude_repo or ''}")
    by_subtag: dict[str, list[dict]] = {}
    for r in pool:
        first = (r["subtag"].split(",")[0] or "unspecified").strip()
        by_subtag.setdefault(first, []).append(r)

    picked: list[dict] = []
    repo_count: dict[str, int] = {}

    def take(r: dict) -> bool:
        if repo_count.get(r["repo"], 0) >= MAX_PER_REPO or len(picked) >= MAX_TRIPLES:
            return False
        picked.append(r)
        repo_count[r["repo"]] = repo_count.get(r["repo"], 0) + 1
        return True

    for subtag in sorted(by_subtag):
        take(rng.choice(by_subtag[subtag]))
    rest = [r for r in pool if r not in picked]
    rng.shuffle(rest)
    for r in rest:
        take(r)
    return picked


def _render_triples(triples: list[dict]) -> str:
    parts = []
    for i, t in enumerate(triples, 1):
        snippet = "\n".join((t["snippet"] or "").splitlines()[:SNIPPET_LINES])
        parts.append(
            f"{i}. subtag: {t['subtag'] or '(none)'}\n"
            f"   fault_pattern: {t['fault_pattern']}\n"
            f"   code:\n```solidity\n{snippet}\n```"
        )
    return "\n\n".join(parts)


def build_induce_prompt(tag: str, tagdef: dict, triples: list[dict],
                        descriptions: list[str], anchors: list[str],
                        feedback: list[str] | None = None) -> tuple[str, str, str]:
    """(system, user, mode). Mode 's2' uses localized triples; 's2b' is the
    degraded definition-only path (model invents the examples)."""
    mode = "s2" if len(triples) >= MIN_TRIPLES else "s2b"
    blocks = [
        f'You are designing a detector for the vulnerability tag "{tag}".',
        "### Official tag definition\n" + tagdef["description"]
        + "\nRelated subtags: " + ", ".join(tagdef["subtags"]),
    ]
    if mode == "s2":
        blocks.append("### Real audited vulnerabilities of this tag "
                      "(localized to code)\n\n" + _render_triples(triples))
    else:
        desc_block = "\n".join(f"- {d}" for d in descriptions[:15]) or "- (none available)"
        blocks.append(
            "### Audit finding descriptions of this tag (no code available)\n"
            + desc_block
            + "\n\nInvent representative Solidity examples yourself; keep them "
              "faithful to the definition above."
        )
    blocks.append(
        "### Style anchors: two existing hand-written detectors\n\n"
        "Match their tone, depth and structure (knowledge, checks, paired "
        "incorrect/correct examples).\n\n"
        + "\n\n---\n\n".join(anchors)
    )
    if feedback:
        blocks.append(
            "### Reviewer feedback from evaluation\n\n"
            "A previous version of this detector was evaluated on real "
            "repositories. Revise the checks accordingly:\n\n"
            + "\n\n".join(feedback)
        )
    blocks.append("### Your task\nOutput the detector JSON now.")
    return INDUCE_SYSTEM, "\n\n".join(blocks), mode


_HINT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_.$]*")


def _valid_detector(d: object) -> bool:
    if not isinstance(d, dict):
        return False
    checks = d.get("checks")
    hints = d.get("routing_hint_candidates")
    return (bool(str(d.get("name") or "").strip())
            and bool(str(d.get("vulnerability_knowledge") or "").strip())
            and isinstance(checks, list) and len(checks) >= 3
            and isinstance(hints, list) and len(hints) >= 3)


def _normalize(d: dict, tag: str) -> dict:
    """Clamp model output into the shape assemble.py renders unconditionally."""
    def ex(key: str) -> dict:
        v = d.get(key)
        if not isinstance(v, dict):
            return {"code": "", "explanation": ""}
        return {"code": str(v.get("code") or ""),
                "explanation": str(v.get("explanation") or "")}

    hints = []
    for h in d.get("routing_hint_candidates") or []:
        m = _HINT_RE.fullmatch(str(h).strip())
        if m and m.group(0) not in hints:
            hints.append(m.group(0))
    return {
        "name": str(d.get("name") or tag).strip(),
        "vulnerability_knowledge": str(d.get("vulnerability_knowledge") or "").strip(),
        "checks": [str(c).strip() for c in (d.get("checks") or [])][:8],
        "incorrect_example": ex("incorrect_example"),
        "correct_example": ex("correct_example"),
        "routing_hint_candidates": hints[:30],
    }


def _fallback_detector(tag: str, tagdef: dict) -> dict:
    """Deterministic last resort when the model twice fails to produce valid JSON:
    definition-derived checks, no examples. Always gated downstream."""
    return {
        "name": tag,
        "vulnerability_knowledge": tagdef["description"],
        "checks": [f"Check for issues matching subtag: {s}"
                   for s in tagdef["subtags"][:8]] or [f"Check for {tag} issues."],
        "incorrect_example": {"code": "", "explanation": ""},
        "correct_example": {"code": "", "explanation": ""},
        "routing_hint_candidates": [],
    }


async def induce_tag(tag: str, tagdef: dict, records: list[dict], client,
                     exclude_repo: str | None = None,
                     feedback: list[str] | None = None,
                     task_id: str | None = None) -> dict:
    """One induction call (plus at most one retry). Returns
    {tag, mode, detector, fallback, triples_used: [Property ids], error}."""
    triples = sample_triples(tag, records, exclude_repo=exclude_repo)
    descriptions = [
        r["description"] for r in records
        if tag in r["tags"] and r["repo"] != (exclude_repo or "")
    ]
    anchors = anchor_texts()
    system, user, mode = build_induce_prompt(
        tag, tagdef, triples, descriptions, anchors, feedback=feedback)

    detector, error, fallback = None, None, False
    for _attempt in range(2):
        res = await client.complete(
            system, user, schema=INDUCE_SCHEMA, temperature=0.3,
            max_tokens=4096, task_id=task_id or f"s2|{tag}")
        error = res.error
        cand = (res.parsed or {}).get("detector") if isinstance(res.parsed, dict) else None
        if _valid_detector(cand):
            detector = _normalize(cand, tag)
            break
    if detector is None:
        detector = _fallback_detector(tag, tagdef)
        fallback = True

    return {
        "tag": tag,
        "mode": mode,
        "detector": detector,
        "fallback": fallback,
        "triples_used": [t["property"] for t in triples],
        "exclude_repo": exclude_repo,
        "error": error,
    }


def save_induction(rec: dict, out_dir: Path) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    from .assemble import slug
    name = slug(rec["tag"]) + (f"__loro_{rec['exclude_repo']}" if rec["exclude_repo"] else "")
    path = out_dir / f"{name}.json"
    path.write_text(json.dumps(rec, indent=1))
    return path


def load_induction(tag: str, out_dir: Path, exclude_repo: str | None = None) -> dict | None:
    from .assemble import slug
    name = slug(tag) + (f"__loro_{exclude_repo}" if exclude_repo else "")
    path = Path(out_dir) / f"{name}.json"
    if path.exists():
        return json.loads(path.read_text())
    return None

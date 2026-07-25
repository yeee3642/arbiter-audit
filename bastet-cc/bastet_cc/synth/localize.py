"""S1 evidence localization: pin each ground-truth description back onto code.

A finding description is written for humans ("rewards are computed from the
pre-fee balance"); synthesis needs the code-level fact behind it. Candidate
retrieval is deterministic -- description tokens vs function identifiers, Jaccard --
so the LLM only ever chooses among functions that share vocabulary with the
description, and its job shrinks to picking the right one and phrasing the
`fault_pattern` in code terms. Descriptions that share no vocabulary with the repo
fall back to a signatures-only listing: the model can still point at a location,
but such findings usually end UNLOCALIZED, which is itself a signal S2b consumes.

Every record is cached by Property id; rerunning the stage only pays for rows that
have no verdict yet.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

LOCALIZE_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "matches": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "contract": {"type": "string"},
                    "function": {"type": "string"},
                    "lines": {"type": "string"},
                    "fault_pattern": {"type": "string"},
                },
            },
        },
        "confidence": {"type": "number"},
        "code_reachable": {"type": "boolean"},
    },
    "required": ["matches", "confidence", "code_reachable"],
}

# UNLOCALIZED threshold (DESIGN §2.3 S1 step 3).
MIN_CONFIDENCE = 0.4
TOP_FUNCTIONS = 12
CHAR_CAP = 12_000
SNIPPET_LINES = 80

_BACKTICK_RE = re.compile(r"`([^`]+)`")
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")
_CAMEL_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z0-9]+")

LOCALIZE_SYSTEM = (
    "You are a smart contract auditor localizing a KNOWN audit finding inside a "
    "Solidity codebase. You are given the finding and candidate functions from the "
    "repository. Identify the function(s) (at most 3, best first) that contain the "
    "described flaw.\n\n"
    "Respond with ONLY a single JSON object, no markdown fences:\n"
    '{"matches": [{"path": "", "contract": "", "function": "", "lines": "L10-L25", '
    '"fault_pattern": ""}], "confidence": 0.0, "code_reachable": true}\n\n'
    "Rules:\n"
    "- Copy path/contract/function EXACTLY from a candidate header.\n"
    "- `fault_pattern` is ONE sentence stating the code-level defect mechanically "
    "(what the code computes/checks/orders wrongly). Do NOT restate the finding "
    "description in prose terms.\n"
    "- `confidence` is your 0..1 estimate that the first match is the true location.\n"
    "- If no candidate plausibly contains the flaw, set code_reachable=false and "
    "matches=[]."
)


def _subtokens(token: str) -> set[str]:
    parts: set[str] = set()
    for piece in token.split("_"):
        for m in _CAMEL_RE.findall(piece):
            if len(m) >= 3:
                parts.add(m.lower())
    return parts


def description_tokens(text: str) -> set[str]:
    """Lowercased token set: backtick contents, identifier-shaped words, and their
    CamelCase/snake_case fragments (DESIGN §2.3 S1 step 1)."""
    out: set[str] = set()
    for inner in _BACKTICK_RE.findall(text or ""):
        for t in _TOKEN_RE.findall(inner):
            out.add(t.lower())
            out |= _subtokens(t)
    for t in _TOKEN_RE.findall(text or ""):
        out.add(t.lower())
        out |= _subtokens(t)
    return out


def _fn_tokens(fn: dict, contract: str) -> set[str]:
    out: set[str] = set()
    for ident in fn.get("identifiers") or []:
        out.add(ident.lower())
        out |= _subtokens(ident)
    for name in (fn.get("name") or "", contract or ""):
        if name:
            out.add(name.lower())
            out |= _subtokens(name)
    return out


def _iter_functions(repo_index: dict):
    for f in repo_index["files"]:
        for fn in f["functions"]:
            yield f["path"], fn


def _has_body(fn: dict) -> bool:
    """Interface / abstract declarations end at the semicolon and cannot contain a
    flaw; measured on TRAIN-SYN they occupied 22.8% of the Jaccard top-12."""
    return "{" in (fn.get("source") or "")


def candidate_functions(repo_index: dict, desc_tokens: set[str]
                        ) -> tuple[list[tuple[str, dict, float]], bool]:
    """Top-12 functions by overlap with the description, capped at 12k chars.

    Returns (candidates, used_fallback). Empty overlap everywhere -> fallback (the
    caller renders a signatures-only listing instead).

    Deviation from DESIGN (pure Jaccard), forced by measurement: Jaccard divides by
    the union, so a four-identifier interface stub sharing one token outranks the
    real 100-identifier implementation sharing six. Median best-overlap on TRAIN-SYN
    is 6 tokens, yet every Jaccard top-12 slot was going to overlap-1 stubs. The
    slate is therefore filled by interleaving the Jaccard ranking with the raw
    overlap-count ranking, so both "most similar" and "most evidence" are
    represented; both orders are deterministic, so the slate still is.
    """
    scored: list[tuple[float, int, str, dict]] = []
    declarations: list[tuple[float, int, str, dict]] = []
    for path, fn in _iter_functions(repo_index):
        toks = _fn_tokens(fn, fn.get("contract", ""))
        inter = len(desc_tokens & toks)
        if inter == 0:
            continue
        row = (inter / len(desc_tokens | toks), inter, path, fn)
        (scored if _has_body(fn) else declarations).append(row)
    if not scored:
        # Only stubs matched: keep them rather than losing the row entirely.
        scored = declarations
    if not scored:
        return [], True

    tie = lambda t: (t[2], t[3]["name"], t[3]["start_line"])
    by_jaccard = sorted(scored, key=lambda t: (-t[0], *tie(t)))
    by_overlap = sorted(scored, key=lambda t: (-t[1], -t[0], *tie(t)))

    slate: list[tuple[float, int, str, dict]] = []
    seen: set[tuple[str, str, int]] = set()
    for i in range(len(scored)):
        for ranking in (by_overlap, by_jaccard):
            if i >= len(ranking):
                continue
            row = ranking[i]
            key = (row[2], row[3]["name"], row[3]["start_line"])
            if key in seen:
                continue
            seen.add(key)
            slate.append(row)
        if len(slate) >= TOP_FUNCTIONS:
            break

    picked: list[tuple[str, dict, float]] = []
    used = 0
    for score, _inter, path, fn in slate[:TOP_FUNCTIONS]:
        src = fn.get("source") or ""
        if picked and used + len(src) > CHAR_CAP:
            continue
        if not picked and len(src) > CHAR_CAP:
            fn = dict(fn, source=src[:CHAR_CAP])
        picked.append((path, fn, score))
        used += len(fn.get("source") or "")
    return picked, False


def signature_listing(repo_index: dict, n_contracts: int = 3) -> str:
    """Signature-only view of the largest contracts, for zero-overlap findings."""
    by_contract: dict[str, list[tuple[str, dict]]] = {}
    for path, fn in _iter_functions(repo_index):
        c = fn.get("contract") or "(free)"
        by_contract.setdefault(c, []).append((path, fn))
    largest = sorted(
        by_contract.items(),
        key=lambda kv: -sum(len(fn.get("source") or "") for _, fn in kv[1]),
    )[:n_contracts]
    lines: list[str] = []
    for contract, fns in largest:
        path = fns[0][0]
        lines.append(f"// FILE {path} | CONTRACT {contract} (signatures only)")
        for _, fn in fns:
            lines.append(
                f"  {fn.get('kind', 'function')} {fn['name']}{fn.get('params', '()')} "
                f"{fn.get('visibility', '')}  // L{fn['start_line']}-L{fn['end_line']}"
            )
    return "\n".join(lines)


def build_localize_prompt(row: dict, repo_index: dict) -> tuple[str, str, bool]:
    """(system, user, used_fallback) for one finding row (raw train.csv columns)."""
    desc = str(row.get("description") or "")
    cands, fallback = candidate_functions(repo_index, description_tokens(desc))
    if fallback:
        code = signature_listing(repo_index)
        note = ("Only contract/function signatures are available; pick the most "
                "plausible location or set code_reachable=false.")
    else:
        parts = []
        for path, fn, _score in cands:
            parts.append(
                f"// FILE {path} | CONTRACT {fn.get('contract', '')} | "
                f"FUNCTION {fn['name']} | L{fn['start_line']}-L{fn['end_line']}\n"
                f"{fn.get('source') or ''}"
            )
        code = "\n\n".join(parts)
        note = ""
    user = "\n\n".join(filter(None, [
        "### Audit finding to localize\n"
        f"- severity: {row.get('severity', '')}\n"
        f"- tag: {row.get('tag', '')}\n"
        f"- subtag: {row.get('subtag', '')}\n"
        f"- description: {desc}",
        note,
        "### Candidate functions from the repository\n\n" + code,
    ]))
    return LOCALIZE_SYSTEM, user, fallback


def _resolve_match(match: dict, repo_index: dict) -> dict | None:
    """Pin a model match to the index: (contract, function) first, then function
    name alone. Unresolvable matches are dropped from evidence (the model drifted)."""
    want_c = str(match.get("contract") or "").strip()
    want_f = str(match.get("function") or "").strip()
    if not want_f:
        return None
    fallback = None
    for path, fn in _iter_functions(repo_index):
        if fn["name"] != want_f:
            continue
        hit = {
            "path": path, "contract": fn.get("contract", ""), "function": fn["name"],
            "start_line": fn["start_line"], "end_line": fn["end_line"],
            "source": fn.get("source") or "",
            "identifiers": list(fn.get("identifiers") or []),
            "lines": str(match.get("lines") or ""),
            "fault_pattern": str(match.get("fault_pattern") or "").strip(),
        }
        if fn.get("contract", "") == want_c:
            return hit
        fallback = fallback or hit
    return fallback


def postprocess(row: dict, result_parsed: dict | None, repo_index: dict,
                fallback_used: bool, error: str | None) -> dict:
    """LLM output -> one persistent localization record (KB-ready shape:
    identifiers + snippet come along for free, DESIGN §1.3 build_kb)."""
    from ..tags import canonical_tag, split_tags

    matches: list[dict] = []
    confidence = 0.0
    reachable = False
    if isinstance(result_parsed, dict):
        try:
            confidence = max(0.0, min(1.0, float(result_parsed.get("confidence", 0.0))))
        except (TypeError, ValueError):
            confidence = 0.0
        reachable = bool(result_parsed.get("code_reachable"))
        for m in (result_parsed.get("matches") or [])[:3]:
            if isinstance(m, dict):
                hit = _resolve_match(m, repo_index)
                if hit is not None:
                    matches.append(hit)

    localized = reachable and confidence >= MIN_CONFIDENCE and bool(matches)
    identifiers = sorted({i for m in matches for i in m["identifiers"]})
    snippet = ""
    if matches:
        snippet = "\n".join(matches[0]["source"].splitlines()[:SNIPPET_LINES])

    return {
        "property": str(row.get("Property", "")),
        "repo": str(row.get("repo_path", "")),
        "severity": str(row.get("severity", "")),
        "tags": [canonical_tag(t) for t in split_tags(row.get("tag"))],
        "subtag": str(row.get("subtag") or ""),
        "description": str(row.get("description") or ""),
        "fault_pattern": matches[0]["fault_pattern"] if matches else "",
        "matches": [{k: v for k, v in m.items() if k != "identifiers"} for m in matches],
        "identifiers": identifiers,
        "snippet": snippet,
        "confidence": confidence,
        "code_reachable": reachable,
        "localized": localized,
        "fallback_candidates": fallback_used,
        "error": error,
    }


async def run_s1(raw_df, repo_indexes: dict[str, dict], client,
                 out_path: Path) -> list[dict]:
    """Localize every TRAIN-SYN finding; cached per Property id in out_path."""
    out_path = Path(out_path)
    cache: dict[str, dict] = {}
    if out_path.exists():
        for rec in json.loads(out_path.read_text()):
            cache[rec["property"]] = rec

    rows = [row for _, row in raw_df.iterrows()]
    pending = [r for r in rows if str(r["Property"]) not in cache]

    calls, metas = [], []
    for row in pending:
        idx = repo_indexes[str(row["repo_path"])]
        system, user, fb = build_localize_prompt(row.to_dict(), idx)
        calls.append({
            "system": system, "user": user, "schema": LOCALIZE_SCHEMA,
            "max_tokens": 1200, "task_id": f"s1|{row['Property']}",
        })
        metas.append((row, idx, fb))

    results = await client.complete_many(calls) if calls else []
    for (row, idx, fb), res in zip(metas, results):
        cache[str(row["Property"])] = postprocess(
            row.to_dict(), res.parsed, idx, fb, res.error)

    records = [cache[str(r["Property"])] for r in rows]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(records, indent=1))
    return records


def localization_rates(records: list[dict]) -> dict[str, dict]:
    """Per-tag localization rate over exploded (finding, tag) pairs."""
    stats: dict[str, dict] = {}
    for rec in records:
        for tag in rec["tags"]:
            s = stats.setdefault(tag, {"n": 0, "localized": 0})
            s["n"] += 1
            s["localized"] += int(rec["localized"])
    for s in stats.values():
        s["rate"] = round(s["localized"] / s["n"], 3) if s["n"] else 0.0
    return dict(sorted(stats.items(), key=lambda kv: (-kv[1]["n"], kv[0])))

"""HERMES: deterministic evidence packets built from the tree-sitter index.

Verification already depends on the indexed repository view rather than on
re-reading source files. HERMES keeps that contract and tightens the selection
logic: only parser-backed relations are admitted, proximity never substitutes
for causality, and every budget decision is repeatable.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .callgraph import CallIndex
from .findings import Finding, asserted_span

try:  # Task 1 lands this; keep Task 2 testable until then.
    from .findings import finding_key
except ImportError:  # pragma: no cover - removed once Task 1 exists
    def finding_key(finding: Finding) -> str:
        parts = [
            finding.repo,
            finding.detector_id,
            finding.tag,
            finding.subtag,
            finding.severity,
            finding.path,
            finding.contract,
            finding.function,
            finding.description,
            finding.evidence,
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


HERMES_VERSION = "v1"
DEFAULT_MAX_CHARS = 12_000

RELATION_ORDER = ("target", "modifier", "caller", "callee", "state_peer")
RELATION_PRIORITY = {name: i for i, name in enumerate(RELATION_ORDER)}

_COMMON_TOKENS = frozenset({
    "", "abi", "address", "assert", "block", "bool", "break", "bytes",
    "calldata", "call", "constructor", "continue", "delegatecall", "delete",
    "do", "else", "emit", "encode", "encodePacked", "encodeWithSelector",
    "encodeWithSignature", "external", "false", "for", "function", "gasleft",
    "if", "int", "internal", "keccak256", "mapping", "memory", "modifier",
    "msg", "new", "override", "payable", "pop", "private", "public", "pure",
    "push", "require", "return", "returns", "revert", "selfdestruct", "send",
    "sender", "sha256", "staticcall", "storage", "string", "super", "this",
    "transfer", "true", "tx", "type", "uint", "var", "view", "virtual",
    "while",
})


@dataclass(frozen=True, slots=True)
class HermesConfig:
    max_chars: int = DEFAULT_MAX_CHARS
    max_metadata_identifiers: int = 8
    version: str = HERMES_VERSION

    def __post_init__(self) -> None:
        if self.max_chars <= 0:
            raise ValueError("max_chars must be positive")
        if self.max_metadata_identifiers <= 0:
            raise ValueError("max_metadata_identifiers must be positive")

    def payload(self) -> dict[str, Any]:
        return {
            "max_chars": self.max_chars,
            "max_metadata_identifiers": self.max_metadata_identifiers,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class EvidenceFragment:
    id: str
    relation: str
    path: str
    contract: str
    function: str
    kind: str
    start_line: int
    end_line: int
    source: str
    provenance: tuple[str, ...] = ()
    shared_count: int = 0
    shared_identifiers: tuple[str, ...] = ()

    def render(self) -> str:
        meta = [
            f"relation={self.relation}",
            f"id={self.id}",
            f"path={self.path}",
            f"contract={self.contract}",
            f"function={self.function}",
            f"kind={self.kind}",
            f"lines=L{self.start_line}-L{self.end_line}",
        ]
        if self.provenance:
            meta.append("provenance=" + ",".join(self.provenance))
        if self.shared_count:
            meta.append(f"shared_count={self.shared_count}")
        if self.shared_identifiers:
            meta.append("shared=" + ",".join(self.shared_identifiers))
        return "// HERMES " + " | ".join(meta) + "\n" + self.source


@dataclass(frozen=True, slots=True)
class EvidencePacket:
    id: str
    finding_id: str
    version: str
    resolution_mode: str
    config: HermesConfig
    target_fragment_id: str
    fragments: tuple[EvidenceFragment, ...]
    relation_counts: tuple[tuple[str, int], ...]
    candidate_counts: tuple[tuple[str, int], ...]
    omitted_counts: tuple[tuple[str, int], ...]
    used_chars: int
    budget_chars: int

    def render(self) -> str:
        return "\n\n".join(fragment.render() for fragment in self.fragments)

    def stats(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "version": self.version,
            "resolution_mode": self.resolution_mode,
            "target_fragment_id": self.target_fragment_id,
            "used_chars": self.used_chars,
            "budget_chars": self.budget_chars,
            "relation_counts": dict(self.relation_counts),
            "candidate_counts": dict(self.candidate_counts),
            "omitted_counts": dict(self.omitted_counts),
        }


@dataclass(frozen=True, slots=True)
class _IndexedDefinition:
    path: str
    contract: str
    name: str
    kind: str
    modifiers: tuple[str, ...]
    start_line: int
    end_line: int
    source: str
    identifiers: frozenset[str]

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.path, self.contract, self.start_line)


def build_packet(finding: Finding, repo_index: dict,
                 config: HermesConfig = HermesConfig()) -> EvidencePacket | None:
    """One deterministic evidence packet, or None when the target cannot resolve."""
    ix = _index_for(repo_index, finding.repo)
    if ix is None:
        return None

    defs = _indexed_defs(ix)
    if not defs:
        return None

    target, resolution_mode = _resolve_target(finding, defs)
    if target is None:
        return None

    defs_by_site = {definition.key: definition for definition in defs}
    call_index = CallIndex(ix)
    doc_freq = _doc_frequency(defs)
    function_names = frozenset(call_index.defined_names)

    modifier_defs = _modifier_defs(target, defs)
    caller_defs = _caller_defs(target, defs)
    callee_defs = _callee_defs(target, call_index, defs_by_site)
    state_peers = _state_peers(target, defs, doc_freq, function_names)

    candidate_counts = {
        "target": 1,
        "modifier": len(modifier_defs),
        "caller": len(caller_defs),
        "callee": len(callee_defs),
        "state_peer": len(state_peers),
    }
    relation_counts = {name: 0 for name in RELATION_ORDER}
    omitted_counts = {name: 0 for name in RELATION_ORDER}

    fragments: list[EvidenceFragment] = []
    used_chars = 0

    target_fragment = _make_fragment(
        "target", target, provenance=(f"resolution:{resolution_mode}",), config=config)
    target_size = len(target_fragment.render())
    if target_size > config.max_chars:
        return None
    fragments.append(target_fragment)
    relation_counts["target"] = 1
    used_chars = target_size

    relation_builders = (
        ("modifier", modifier_defs, lambda item: _make_fragment(
            "modifier", item, provenance=("modifier_invocation",), config=config)),
        ("caller", caller_defs, lambda item: _make_fragment(
            "caller", item, provenance=("reverse_identifier_membership",), config=config)),
        ("callee", callee_defs, lambda item: _make_fragment(
            "callee", item[0], provenance=item[1], config=config)),
        ("state_peer", state_peers, lambda item: _make_fragment(
            "state_peer", item[0],
            provenance=("shared_rare_identifiers",),
            shared_identifiers=item[1],
            shared_count=len(item[1]),
            config=config)),
    )

    for relation, items, builder in relation_builders:
        for item in items:
            fragment = builder(item)
            addition = len(fragment.render()) + 2
            if used_chars + addition > config.max_chars:
                omitted_counts[relation] += 1
                continue
            fragments.append(fragment)
            relation_counts[relation] += 1
            used_chars += addition
        if relation_counts[relation] < candidate_counts[relation]:
            omitted_counts[relation] += (
                candidate_counts[relation] - relation_counts[relation] - omitted_counts[relation]
            )

    packet = EvidencePacket(
        id=_stable_id({
            "finding_id": str(finding_key(finding)),
            "config": config.payload(),
            "resolution_mode": resolution_mode,
            "fragments": [fragment.id for fragment in fragments],
            "relation_counts": _freeze_counts(relation_counts),
            "candidate_counts": _freeze_counts(candidate_counts),
            "omitted_counts": _freeze_counts(omitted_counts),
            "used_chars": used_chars,
        }),
        finding_id=str(finding_key(finding)),
        version=config.version,
        resolution_mode=resolution_mode,
        config=config,
        target_fragment_id=target_fragment.id,
        fragments=tuple(fragments),
        relation_counts=_freeze_counts(relation_counts),
        candidate_counts=_freeze_counts(candidate_counts),
        omitted_counts=_freeze_counts(omitted_counts),
        used_chars=used_chars,
        budget_chars=config.max_chars,
    )
    return packet


def _index_for(repo_index: dict, repo: str) -> dict | None:
    if "files" in repo_index:
        return repo_index
    got = repo_index.get(repo)
    return got if isinstance(got, dict) and "files" in got else None


def _indexed_defs(repo_index: dict) -> list[_IndexedDefinition]:
    defs: list[_IndexedDefinition] = []
    for fobj in repo_index.get("files", []):
        for fn in fobj.get("functions", []):
            defs.append(_IndexedDefinition(
                path=fobj["path"],
                contract=fn["contract"],
                name=fn["name"],
                kind=fn.get("kind", "function"),
                modifiers=tuple(fn.get("modifiers") or []),
                start_line=fn["start_line"],
                end_line=fn["end_line"],
                source=fn["source"],
                identifiers=frozenset(fn.get("identifiers") or ()),
            ))
    return defs


def _candidate_paths(path: str, defs: list[_IndexedDefinition]) -> set[str]:
    exact = {definition.path for definition in defs if definition.path == path}
    if exact:
        return exact
    return {definition.path for definition in defs if definition.path.endswith(path)}


def _resolve_target(finding: Finding,
                    defs: list[_IndexedDefinition]) -> tuple[_IndexedDefinition | None, str]:
    paths = _candidate_paths(finding.path, defs)
    if not paths:
        return None, "unresolved"
    scoped = [definition for definition in defs if definition.path in paths]

    if finding.start_line > 0:
        exact = [
            definition for definition in scoped
            if definition.contract == finding.contract
            and definition.name == finding.function
            and definition.start_line == finding.start_line
        ]
        if exact:
            exact.sort(key=lambda definition: (
                definition.path, definition.contract, definition.start_line, definition.name))
            return exact[0], "parser_identity"

    same_name = [
        definition for definition in scoped
        if definition.contract == finding.contract and definition.name == finding.function
    ]
    if same_name:
        same_name.sort(key=lambda definition: (
            definition.path, definition.contract, definition.start_line, definition.name))
        return same_name[0], "function_fallback"

    by_name = [definition for definition in scoped if definition.name == finding.function]
    if by_name:
        by_name.sort(key=lambda definition: (
            definition.path, definition.contract, definition.start_line, definition.name))
        return by_name[0], "function_fallback"

    span = asserted_span(finding)
    if span is None:
        return None, "unresolved"
    overlapping = [
        definition for definition in scoped
        if definition.start_line <= span[1] and definition.end_line >= span[0]
    ]
    if not overlapping:
        return None, "unresolved"
    overlapping.sort(key=lambda definition: (
        -_overlap(span, definition), definition.path, definition.contract,
        definition.start_line, definition.name))
    return overlapping[0], "evidence_overlap"


def _overlap(span: tuple[int, int], definition: _IndexedDefinition) -> int:
    return min(span[1], definition.end_line) - max(span[0], definition.start_line) + 1


def _modifier_defs(target: _IndexedDefinition,
                   defs: list[_IndexedDefinition]) -> list[_IndexedDefinition]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in target.modifiers:
        name = raw.split("(", 1)[0].strip()
        if name and name not in seen:
            seen.add(name)
            normalized.append(name)

    out: list[_IndexedDefinition] = []
    for name in normalized:
        matches = [definition for definition in defs
                   if definition.kind == "modifier" and definition.name == name]
        same_contract = [definition for definition in matches
                         if definition.contract == target.contract]
        chosen = same_contract or matches
        out.extend(chosen)
    return sorted(
        out,
        key=lambda definition: _rank_tuple("modifier", target, definition, 0),
    )


def _caller_defs(target: _IndexedDefinition,
                 defs: list[_IndexedDefinition]) -> list[_IndexedDefinition]:
    matches = [
        definition for definition in defs
        if definition.key != target.key and target.name in definition.identifiers
    ]
    return sorted(matches, key=lambda definition: _rank_tuple("caller", target, definition, 0))


def _callee_defs(target: _IndexedDefinition, call_index: CallIndex,
                 defs_by_site: dict[tuple[str, str, int], _IndexedDefinition]
                 ) -> list[tuple[_IndexedDefinition, tuple[str, ...]]]:
    names = sorted({
        ident for ident in target.identifiers
        if "." not in ident
        and ident != target.name
        and ident not in _COMMON_TOKENS
        and ident in call_index.defined_names
    })
    resolved: list[tuple[_IndexedDefinition, tuple[str, ...]]] = []
    for name in names:
        refs = [
            defs_by_site[(ref.path, ref.contract, ref.start_line)]
            for ref in call_index.resolve(target.contract, name)
            if (ref.path, ref.contract, ref.start_line) in defs_by_site
        ]
        refs = [definition for definition in refs if definition.key != target.key]
        refs.sort(key=lambda definition: _rank_tuple("callee", target, definition, 0))
        ambiguous = len(refs) > 1
        for definition in refs:
            provenance = ["call_index"]
            if ambiguous:
                provenance.append("ambiguous_name")
            resolved.append((definition, tuple(provenance)))
    return sorted(
        resolved,
        key=lambda item: _rank_tuple("callee", target, item[0], 0),
    )


def _state_peers(target: _IndexedDefinition, defs: list[_IndexedDefinition],
                 doc_freq: dict[str, int], function_names: frozenset[str]
                 ) -> list[tuple[_IndexedDefinition, tuple[str, ...]]]:
    total_defs = max(len(defs), 1)
    target_terms = _state_terms(target, doc_freq, total_defs, function_names)
    peers: list[tuple[_IndexedDefinition, tuple[str, ...]]] = []

    for definition in defs:
        if definition.key == target.key:
            continue
        if definition.contract != target.contract:
            continue
        if definition.kind == "modifier":
            continue
        shared = sorted(
            target_terms & _state_terms(definition, doc_freq, total_defs, function_names))
        if not shared:
            continue
        peers.append((definition, tuple(shared)))

    peers.sort(key=lambda item: _rank_tuple(
        "state_peer", target, item[0], len(item[1])))
    return peers


def _doc_frequency(defs: list[_IndexedDefinition]) -> dict[str, int]:
    freq: dict[str, int] = {}
    for definition in defs:
        for ident in set(definition.identifiers):
            freq[ident] = freq.get(ident, 0) + 1
    return freq


def _state_terms(definition: _IndexedDefinition, doc_freq: dict[str, int],
                 total_defs: int, function_names: frozenset[str]) -> set[str]:
    out: set[str] = set()
    for ident in definition.identifiers:
        if len(ident) <= 1:
            continue
        if ident in function_names:
            continue
        if ident in _COMMON_TOKENS:
            continue
        freq = doc_freq.get(ident, 0)
        if freq <= 1:
            continue
        if freq * 2 > total_defs:
            continue
        out.add(ident)
    return out


def _make_fragment(relation: str, definition: _IndexedDefinition, *,
                   provenance: tuple[str, ...], config: HermesConfig,
                   shared_identifiers: tuple[str, ...] = (),
                   shared_count: int = 0) -> EvidenceFragment:
    limited_shared = shared_identifiers[:config.max_metadata_identifiers]
    return EvidenceFragment(
        id=_stable_id({
            "relation": relation,
            "path": definition.path,
            "contract": definition.contract,
            "function": definition.name,
            "kind": definition.kind,
            "start_line": definition.start_line,
            "end_line": definition.end_line,
            "source": definition.source,
            "provenance": list(provenance),
            "shared_count": shared_count,
            "shared_identifiers": list(limited_shared),
        }),
        relation=relation,
        path=definition.path,
        contract=definition.contract,
        function=definition.name,
        kind=definition.kind,
        start_line=definition.start_line,
        end_line=definition.end_line,
        source=definition.source,
        provenance=provenance,
        shared_count=shared_count,
        shared_identifiers=limited_shared,
    )


def _rank_tuple(relation: str, target: _IndexedDefinition,
                definition: _IndexedDefinition, shared_count: int) -> tuple[Any, ...]:
    return (
        RELATION_PRIORITY[relation],
        -shared_count,
        0 if definition.contract == target.contract else 1,
        abs(definition.start_line - target.start_line),
        definition.path,
        definition.contract,
        definition.start_line,
        definition.name,
    )


def _freeze_counts(counts: dict[str, int]) -> tuple[tuple[str, int], ...]:
    return tuple((relation, counts.get(relation, 0)) for relation in RELATION_ORDER)


def _stable_id(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

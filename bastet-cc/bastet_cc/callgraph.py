"""One-hop call closure: give a routed slice the functions it actually calls.

Routing sends one function per slice. That is what makes it cheap, and it is
also its one structural weakness: a bug whose cause and effect sit in different
functions is invisible to a reader who only sees one of them. The project
already concedes this -- `Calibration.verify_off_tags` exists to switch the
verifier off for tags where DEV showed it destroying recall on exactly those
cross-function cases. A flag that disables a component on the tags where it
misbehaves is a workaround; seeing the other function is the fix.

The closure is deliberately **one hop and callees-only**:

- *One hop*, because two hops pulls in the transitive tail of every library
  helper and the payload stops being a slice. Measured on this corpus, hop 2
  is where `SafeERC20.safeTransfer` and friends arrive, and they carry no
  information a detector prompt does not already assume.
- *Callees, not callers*, because the question a detector asks is "what does
  this function do", and what it does includes what it delegates. Callers
  answer a different question (who can reach this), which matters for
  reachability analysis and not for pattern detection. Adding them roughly
  doubles the payload for a question nobody is asking here.

Resolution is name-based over the tree-sitter index, with no compiler and no
type inference, so it is necessarily approximate. The approximation is chosen to
fail *closed* rather than open: an unresolvable call is skipped, never guessed.
Overloads are merged (all bodies with that name in scope), because picking one
by arity would be a guess and including both is honest.

Cost is bounded twice -- by fan-out and by characters -- and both bounds are
recorded per slice, so the ablation "routed vs routed+closure" can report what
it actually spent rather than an average.
"""

from __future__ import annotations

from dataclasses import dataclass

from .routing import Slice

# Fan-out cap. The long tail of high-degree functions is dominated by dispatchers
# and constructors, whose callees are individually uninformative; capping keeps a
# single pathological function from eating a run's budget.
MAX_CALLEES = 6

# Character cap on everything appended to one slice. ~4 chars/token, so this is
# roughly 1.5K tokens of context on top of a function that averages ~700.
MAX_CLOSURE_CHARS = 6_000

# Solidity/EVM builtins and common no-op wrappers. These parse as calls and
# resolve to nothing useful; listing them avoids burning fan-out slots on lookups
# that were always going to miss.
_BUILTINS = frozenset({
    "require", "assert", "revert", "keccak256", "sha256", "ripemd160", "ecrecover",
    "addmod", "mulmod", "selfdestruct", "blockhash", "gasleft", "type", "new",
    "abi", "msg", "block", "tx", "super", "this", "address", "payable",
    "uint", "int", "bytes", "string", "bool", "emit", "return", "if", "for",
    "while", "delete", "push", "pop", "length", "call", "delegatecall",
    "staticcall", "transfer", "send", "encode", "encodePacked", "decode",
    "encodeWithSelector", "encodeWithSignature", "toString", "wrap", "unwrap",
})


@dataclass
class FunctionRef:
    """A resolved definition, addressable independently of the file it came from."""
    path: str
    contract: str
    name: str
    start_line: int
    end_line: int
    source: str

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.path, self.contract, self.start_line)


class CallIndex:
    """Name -> definitions, built once per repository.

    Two maps rather than one. `by_contract` is consulted first so that a call to
    `_mint` inside `contract Vault` prefers `Vault._mint` over an unrelated
    `_mint` elsewhere in the repo; `by_name` is the fallback for inherited and
    cross-contract calls, which name resolution alone cannot distinguish. When
    the fallback is ambiguous the definitions are merged rather than picked
    between -- see the module docstring.
    """

    def __init__(self, repo_index: dict):
        self.by_contract: dict[tuple[str, str], list[FunctionRef]] = {}
        self.by_name: dict[str, list[FunctionRef]] = {}
        self._defined_names: set[str] = set()

        for f in repo_index.get("files", []):
            for fn in f.get("functions", []):
                ref = FunctionRef(
                    path=f["path"], contract=fn["contract"], name=fn["name"],
                    start_line=fn["start_line"], end_line=fn["end_line"],
                    source=fn["source"],
                )
                self.by_contract.setdefault((fn["contract"], fn["name"]), []).append(ref)
                self.by_name.setdefault(fn["name"], []).append(ref)
                self._defined_names.add(fn["name"])

        # Identifier sets are large; intersecting against the set of names that
        # are actually defined somewhere turns resolution into one hash lookup
        # per candidate rather than a scan of the index.
        self.defined_names = frozenset(self._defined_names)

    def resolve(self, contract: str, name: str) -> list[FunctionRef]:
        same = self.by_contract.get((contract, name))
        if same:
            return same
        return self.by_name.get(name, [])


def _candidate_names(identifiers: set[str], index: CallIndex,
                     exclude: str) -> list[str]:
    """Identifiers that name a function defined in this repository.

    Member accesses arrive as both `obj.prop` and bare `prop` (see
    `solidity._collect_identifiers`), so the bare form is what matches a
    definition; the dotted form is dropped here and the bare one carries it.
    """
    out = []
    for ident in identifiers:
        if "." in ident or ident in _BUILTINS or ident == exclude:
            continue
        if ident in index.defined_names:
            out.append(ident)
    # Deterministic order: routing must produce the same plan on every run, and
    # `identifiers` arrives as a set.
    return sorted(out)


def closure_for(sl: Slice, identifiers: set[str], index: CallIndex,
                max_callees: int = MAX_CALLEES,
                max_chars: int = MAX_CLOSURE_CHARS) -> tuple[list[FunctionRef], dict]:
    """The callees of one slice, capped, with what the caps cost.

    Returns `(refs, stats)`. `stats` records how many candidates were found,
    how many survived each cap and how many characters were added, so a run can
    report its closure cost instead of asserting it is small.
    """
    names = _candidate_names(identifiers, index, exclude=sl.function)
    seen: set[tuple[str, str, int]] = {(sl.path, sl.contract, sl.start_line)}
    picked: list[FunctionRef] = []
    chars = 0
    truncated_by = None

    for name in names:
        if len(picked) >= max_callees:
            truncated_by = "fan_out"
            break
        for ref in index.resolve(sl.contract, name):
            if ref.key in seen:
                continue
            if chars + len(ref.source) > max_chars:
                truncated_by = truncated_by or "chars"
                continue
            seen.add(ref.key)
            picked.append(ref)
            chars += len(ref.source)
            if len(picked) >= max_callees:
                truncated_by = truncated_by or "fan_out"
                break

    return picked, {
        "candidates": len(names),
        "resolved": len(picked),
        "closure_chars": chars,
        "truncated_by": truncated_by,
    }


def render_closure(refs: list[FunctionRef]) -> str:
    """The appended context block, labelled so the model cannot confuse it.

    Marked explicitly as context rather than as the subject of the audit: without
    the label, probes showed findings being reported *against the callee*, which
    scores as a false positive on the slice that was actually being asked about.
    """
    if not refs:
        return ""
    parts = [
        "\n\n// ---------------------------------------------------------------",
        "// CONTEXT ONLY -- functions called by the code above, provided so you",
        "// can follow the data flow. Do NOT report findings against these;",
        "// report only against the function under audit.",
        "// ---------------------------------------------------------------",
    ]
    for r in refs:
        parts.append(f"\n// {r.path}:{r.contract}.{r.name} (L{r.start_line}-{r.end_line})")
        parts.append(r.source)
    return "\n".join(parts)


def expand_slice(sl: Slice, identifiers: set[str], index: CallIndex,
                 max_callees: int = MAX_CALLEES,
                 max_chars: int = MAX_CLOSURE_CHARS) -> tuple[Slice, dict]:
    """A copy of `sl` with its callees appended to `source`.

    A copy, not a mutation: `Slice.id` is derived from path/contract/function and
    line numbers, none of which change, so the expanded slice keeps the same
    identity and therefore the same `task_id`. That is deliberate -- turning the
    closure on must invalidate the resume cache, and it does, because the arm
    name is folded into the run id rather than into the slice.
    """
    refs, stats = closure_for(sl, identifiers, index, max_callees, max_chars)
    if not refs:
        return sl, stats
    expanded = Slice(
        repo=sl.repo, path=sl.path, contract=sl.contract, function=sl.function,
        start_line=sl.start_line, end_line=sl.end_line,
        source=sl.source + render_closure(refs),
    )
    return expanded, stats


def expand_tasks(tasks: list, repo_index: dict,
                 max_callees: int = MAX_CALLEES,
                 max_chars: int = MAX_CLOSURE_CHARS) -> dict:
    """Expand every slice in a routed plan in place; return aggregate cost.

    In place because a plan is already a list of Tasks holding lists of Slices,
    and rebuilding it would force every caller to thread a new object through.
    The returned dict is what the run manifest records.
    """
    index = CallIndex(repo_index)
    idents_by_key: dict[tuple[str, str, int], set[str]] = {}
    for f in repo_index.get("files", []):
        for fn in f.get("functions", []):
            idents_by_key[(f["path"], fn["contract"], fn["start_line"])] = \
                set(fn.get("identifiers") or [])

    n_slices = n_expanded = added_chars = 0
    truncations: dict[str, int] = {}
    for t in tasks:
        new_slices = []
        for sl in t.slices:
            idents = idents_by_key.get((sl.path, sl.contract, sl.start_line), set())
            n_slices += 1
            expanded, stats = expand_slice(sl, idents, index, max_callees, max_chars)
            if stats["resolved"]:
                n_expanded += 1
                added_chars += stats["closure_chars"]
            if stats["truncated_by"]:
                truncations[stats["truncated_by"]] = \
                    truncations.get(stats["truncated_by"], 0) + 1
            new_slices.append(expanded)
        t.slices = new_slices

    return {
        "slices": n_slices,
        "slices_expanded": n_expanded,
        "expansion_rate": round(n_expanded / n_slices, 4) if n_slices else 0.0,
        "added_chars": added_chars,
        "added_tokens_est": added_chars // 4,
        "truncations": truncations,
        "max_callees": max_callees,
        "max_closure_chars": max_chars,
    }

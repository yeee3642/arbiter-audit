"""A second tier of evidence, for defects an EVM cannot be made to demonstrate.

The execution gate is the strongest thing in this project and it has a hard boundary.
Slippage is the clearest case: "this swap passes zero as its minimum output" is a real
defect with a real victim, but demonstrating it needs a live automated market maker, an
adversarial ordering, and a victim transaction -- none of which exist inside a single
repository's test harness. A tool that can only report what it can execute answers "safe"
to that entire class, which is a degenerate predictor pointed the other way from a
53-detector OR that answers "vulnerable" to everything.

So there is a second tier, and it is a tier rather than an exception because the property
that matters is preserved: **the model cannot assert its way to a positive**. It selects a
site and explains the impact; the harness re-derives the defect from the source itself and
rejects the claim if its own reading disagrees. What travels in the record is not "the
model said so" but "the harness parsed this call, found the argument in the slippage
position, and it is the literal zero".

Reported separately from executed proofs, always. A verified citation is weaker evidence
than a transaction that ran, and conflating them would give away the only thing that makes
the first tier worth having.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Router and pool entry points whose argument positions are fixed by their published
# interfaces. Position is what makes this mechanical: for these, the harness does not have
# to guess which argument bounds the trade.
#   name -> (arity, {"bound": index or None, "deadline": index or None})
KNOWN_SITES: dict[str, tuple[int, dict[str, int]]] = {
    "swapExactTokensForTokens": (5, {"bound": 1, "deadline": 4}),
    "swapExactTokensForTokensSupportingFeeOnTransferTokens": (5, {"bound": 1, "deadline": 4}),
    "swapTokensForExactTokens": (5, {"bound": 1, "deadline": 4}),
    "swapExactETHForTokens": (4, {"bound": 0, "deadline": 3}),
    "swapExactETHForTokensSupportingFeeOnTransferTokens": (4, {"bound": 0, "deadline": 3}),
    "swapETHForExactTokens": (4, {"bound": 0, "deadline": 3}),
    "swapExactTokensForETH": (5, {"bound": 1, "deadline": 4}),
    "swapExactTokensForETHSupportingFeeOnTransferTokens": (5, {"bound": 1, "deadline": 4}),
    "swapTokensForExactETH": (5, {"bound": 1, "deadline": 4}),
    "addLiquidity": (8, {"bound": 4, "deadline": 7}),
    "addLiquidityETH": (6, {"bound": 2, "deadline": 5}),
    "removeLiquidity": (7, {"bound": 3, "deadline": 6}),
    "removeLiquidityETH": (6, {"bound": 2, "deadline": 5}),
    # Curve
    "exchange": (4, {"bound": 3}),
    "exchange_underlying": (4, {"bound": 3}),
    "remove_liquidity_one_coin": (3, {"bound": 2}),
    # Generic vault / market shapes seen in the corpus
    "redeemUnderlying": (2, {"bound": 1}),
    "swap": (4, {"bound": 3}),
}

# Parameter names that carry a trade bound, for callees the table does not know. Matching
# is on the DECLARATION, so the harness learns the position from the code rather than
# assuming it.
BOUND_PARAM_RE = re.compile(
    r"\b(?:amountOutMin|amountOutMinimum|minAmountOut|minOut|minReturn|minTokens|"
    r"minShares|minAssets|min_dy|minDy|amountInMax|maxAmountIn|maxIn|slippage|"
    r"sqrtPriceLimitX96|limit)\w*\b",
    re.IGNORECASE,
)
DEADLINE_PARAM_RE = re.compile(r"\b(?:deadline|expiry|validUntil)\w*\b", re.IGNORECASE)

ZERO_RE = re.compile(r"^(?:0|0x0+|uint256\(0\)|uint\(0\)|type\(uint\d*\)\.min)$")
NOW_RE = re.compile(r"^(?:block\.timestamp|now|type\(uint\d*\)\.max|\d{10,})$")

FUNCTION_DECL_RE = re.compile(
    r"function\s+(\w+)\s*\(([^)]*)\)([^{;]*)", re.DOTALL
)


@dataclass
class Site:
    """One call the harness believes is unbounded, with the reading that says so."""

    kind: str            # min_out_zero | min_out_missing | deadline_now
    callee: str
    expression: str      # verbatim, as it appears in the file
    argument: str        # the argument the harness objects to
    position: int
    enclosing: str       # the function it sits in
    line: int

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind, "callee": self.callee, "expression": self.expression,
            "argument": self.argument, "position": self.position,
            "enclosing": self.enclosing, "line": self.line,
        }


def split_args(text: str) -> list[str]:
    """Split a call's argument list on top-level commas only.

    Nested calls, array literals and struct literals all contain commas that are not
    argument separators, and getting this wrong would put the harness's objection on the
    wrong argument -- which is exactly the kind of confident-and-wrong claim this tier
    exists to avoid.
    """
    out: list[str] = []
    depth = 0
    current: list[str] = []
    in_string: str | None = None
    for ch in text:
        if in_string:
            current.append(ch)
            if ch == in_string:
                in_string = None
            continue
        if ch in "\"'":
            in_string = ch
            current.append(ch)
        elif ch in "([{":
            depth += 1
            current.append(ch)
        elif ch in ")]}":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        out.append(tail)
    return out


def _call_span(source: str, start: int) -> tuple[str, int] | None:
    """From the '(' at `start`, return (inner text, index just past the ')')."""
    depth = 0
    for i in range(start, len(source)):
        if source[i] == "(":
            depth += 1
        elif source[i] == ")":
            depth -= 1
            if depth == 0:
                return source[start + 1:i], i + 1
    return None


def _enclosing_function(source: str, index: int) -> tuple[str, str]:
    """The name and parameter list of the function containing `index`."""
    best = ("(file scope)", "")
    for match in FUNCTION_DECL_RE.finditer(source):
        if match.start() > index:
            break
        best = (match.group(1), match.group(2))
    return best


def declared_bounds(source: str, callee: str) -> dict[str, int] | None:
    """Learn a callee's bound and deadline positions from its declaration in `source`."""
    for match in re.finditer(rf"function\s+{re.escape(callee)}\s*\(([^)]*)\)", source):
        params = split_args(match.group(1))
        found: dict[str, int] = {}
        for i, param in enumerate(params):
            name = param.strip().split()[-1] if param.strip() else ""
            if "bound" not in found and BOUND_PARAM_RE.search(name):
                found["bound"] = i
            if "deadline" not in found and DEADLINE_PARAM_RE.search(name):
                found["deadline"] = i
        if found:
            return found
    return None


def scan_slippage(source: str, declarations: str = "") -> list[Site]:
    """Every trade-like call in `source` whose bound the harness reads as absent.

    `declarations` is additional Solidity -- the interfaces the file imports -- so a
    callee the fixed table does not know can still have its argument positions learned
    from its own signature rather than guessed.
    """
    sites: list[Site] = []
    haystack = source + "\n" + declarations

    for match in re.finditer(r"\.\s*(\w+)\s*(?=\()", source):
        callee = match.group(1)
        paren = source.index("(", match.end() - 1)
        span = _call_span(source, paren)
        if span is None:
            continue
        inner, end = span
        args = split_args(inner)

        positions: dict[str, int] | None = None
        if callee in KNOWN_SITES:
            arity, positions = KNOWN_SITES[callee]
            if len(args) != arity:
                positions = None       # not the interface we know; do not guess
        if positions is None:
            positions = declared_bounds(haystack, callee) or {}
        if not positions:
            continue

        expression = " ".join(source[match.start() + 1:end].split())
        line = source.count("\n", 0, match.start()) + 1
        fn_name, fn_params = _enclosing_function(source, match.start())

        bound = positions.get("bound")
        if bound is not None and bound < len(args):
            argument = args[bound]
            if ZERO_RE.match(argument.strip()):
                sites.append(Site("min_out_zero", callee, expression, argument, bound,
                                  fn_name, line))
            elif not _derived_from_caller(argument, fn_params):
                sites.append(Site("min_out_missing", callee, expression, argument, bound,
                                  fn_name, line))

        due = positions.get("deadline")
        if due is not None and due < len(args) and NOW_RE.match(args[due].strip()):
            sites.append(Site("deadline_now", callee, expression, args[due], due,
                              fn_name, line))
    sites += scan_struct_bounds(source)
    sites += scan_unbounded_entrypoints(source)
    return sites


def scan_struct_bounds(source: str) -> list[Site]:
    """Bounds passed as named struct fields rather than positional arguments.

    Modern routers take a parameter struct -- `ExactInputSingleParams({...,
    amountOutMinimum: 0, sqrtPriceLimitX96: 0})` -- so the whole positional analysis above
    sees a single argument and finds nothing. The field name is the position here, which
    is if anything more reliable: it is the interface author's own word for what the
    argument bounds.
    """
    sites: list[Site] = []
    pattern = re.compile(
        r"\b(amountOutMinimum|amountOutMin|minAmountOut|minOut|amountInMaximum|"
        r"minReturn|minShares|minAssets|min_dy|sqrtPriceLimitX96|deadline)\s*:\s*"
        r"([^,\n}]+)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(source):
        field_name, value = match.group(1), match.group(2).strip()
        line = source.count("\n", 0, match.start()) + 1
        fn_name, fn_params = _enclosing_function(source, match.start())
        expression = " ".join(match.group(0).split())
        is_deadline = field_name.lower().startswith(("deadline", "expiry"))
        if is_deadline:
            if NOW_RE.match(value):
                sites.append(Site("deadline_now", field_name, expression, value, -1,
                                  fn_name, line))
            continue
        # sqrtPriceLimitX96 is conventionally zero even in careful code, so it is only
        # evidence when it is the ONLY bound in that struct -- checked by the caller.
        if ZERO_RE.match(value):
            sites.append(Site("min_out_zero", field_name, expression, value, -1,
                              fn_name, line))
        elif not _derived_from_caller(value, fn_params):
            sites.append(Site("min_out_missing", field_name, expression, value, -1,
                              fn_name, line))
    return sites


TRADE_CALL_RE = re.compile(
    r"\.\s*(\w*(?:swap|exchange|trade|convert|zap|addLiquidity|removeLiquidity)\w*)\s*\(",
    re.IGNORECASE,
)
# A hand-written bound: something in the body is compared against a value the caller
# supplied. `require(out >= minOut)` is the canonical shape, but the check can also be an
# if/revert, so the test is a comparison operator with a parameter on either side.
COMPARISON_RE = re.compile(r"[<>]=?|==")


def _function_bodies(source: str):
    """Yield (name, params, modifiers, body, line) for every function with a body."""
    for match in FUNCTION_DECL_RE.finditer(source):
        brace = source.find("{", match.end() - 1)
        if brace == -1:
            continue
        # Reject a declaration whose ';' comes before its '{' -- that is an interface
        # method, and the next contract's opening brace is not its body.
        semi = source.find(";", match.end() - 1)
        if semi != -1 and semi < brace:
            continue
        depth, end = 0, -1
        for i in range(brace, len(source)):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end == -1:
            continue
        yield (
            match.group(1), match.group(2), match.group(3) or "",
            source[brace:end], source.count("\n", 0, match.start()) + 1,
        )


def scan_unbounded_entrypoints(source: str) -> list[Site]:
    """Externally reachable functions that trade and accept no bound at all.

    This is the shape behind "Missing minOut / maxAmount", 25 of the 46 curated slippage
    findings and every one the positional reader missed. There is no zero to point at
    because there is no bound anywhere: the entry point simply does not let its caller say
    what price is unacceptable, so whatever the pool gives back is what they get.

    Deliberately narrow, since this fires without a literal to anchor on. The function has
    to be externally reachable, mutate state, actually perform a trade, take no parameter
    whose name is a bound, and contain no hand-written comparison against a value the
    caller supplied.
    """
    sites: list[Site] = []
    for name, params, mods, body, line in _function_bodies(source):
        if not re.search(r"\b(external|public)\b", mods):
            continue
        if re.search(r"\b(view|pure)\b", mods):
            continue
        trade = TRADE_CALL_RE.search(body)
        if not trade:
            continue
        if BOUND_PARAM_RE.search(params):
            continue
        param_names = {
            p.strip().split()[-1]
            for p in split_args(params)
            if p.strip() and len(p.strip().split()) >= 2
        }
        guarded = any(
            COMPARISON_RE.search(line_text) and any(
                re.search(rf"\b{re.escape(pn)}\b", line_text) for pn in param_names if pn
            )
            for line_text in body.splitlines()
            if "require" in line_text or "revert" in line_text
        )
        if guarded:
            continue
        sites.append(
            Site(
                "min_out_missing_param", trade.group(1),
                " ".join(f"function {name}({params})".split()),
                "(no bound parameter)", -1, name, line,
            )
        )
    return sites


def repo_declarations(paths: list[str]) -> str:
    """Concatenate the function signatures in a repository, for position learning.

    Only signatures, because bodies are the bulk of the bytes and none of the
    information: what is needed is which parameter of `swapExactTokensForTokens` is the
    minimum, and that is in the declaration.
    """
    chunks: list[str] = []
    for text in paths:
        chunks += [m.group(0) for m in FUNCTION_DECL_RE.finditer(text)]
    return "\n".join(chunks)


def _derived_from_caller(argument: str, params: str) -> bool:
    """Does this bound trace back to something the caller chose?

    A minimum the contract computes for itself is not slippage protection -- the caller
    cannot refuse a bad price they were never allowed to set. So a bound counts only when
    it mentions a parameter of the enclosing function.
    """
    names = {
        p.strip().split()[-1]
        for p in split_args(params)
        if p.strip() and len(p.strip().split()) >= 2
    }
    return any(re.search(rf"\b{re.escape(n)}\b", argument) for n in names if n)


@dataclass
class Verdict:
    ok: bool
    reason: str = ""
    site: Site | None = None
    alternatives: list[Site] = field(default_factory=list)


def verify(source: str, expression: str, kind: str, declarations: str = "") -> Verdict:
    """Check a model's citation against the harness's own reading of the source.

    Rejects when the expression is not in the file, when the harness does not read that
    call as unbounded, or when it disagrees about which defect it is. What the run keeps
    is the harness's reading, never the model's.
    """
    squash = lambda s: re.sub(r"\s+", " ", s).strip()  # noqa: E731
    if not expression.strip():
        return Verdict(False, "no expression cited")
    if squash(expression) not in squash(source):
        return Verdict(False, "the cited expression does not appear in that file")

    sites = scan_slippage(source, declarations)
    target = squash(expression)
    for site in sites:
        if squash(site.expression) in target or target in squash(site.expression):
            if site.kind != kind:
                return Verdict(
                    False,
                    f"the harness reads that call as {site.kind!r}, not {kind!r}",
                    site, sites,
                )
            return Verdict(True, "", site, sites)
    return Verdict(
        False,
        "the harness does not read that call as missing a trade bound: either it is not "
        "a trade, or its bound is supplied by a parameter of the enclosing function",
        None, sites,
    )

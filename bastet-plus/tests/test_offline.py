"""Offline tests -- no network, no model. Run: python -m tests.test_offline"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bastet_plus.grounding import SourceIndex, apply_grounding          # noqa: E402
from bastet_plus.llm import extract_json                                # noqa: E402
from bastet_plus.metrics import Confusion, evaluate, wilson             # noqa: E402
from bastet_plus.schema import Finding, coerce_findings                 # noqa: E402
from bastet_plus.slicing import read_source, slice_solidity             # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
FAILED = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name} {detail}")
        FAILED.append(name)


print("extract_json")
check("bare object", extract_json('{"a":1}') == {"a": 1})
check("fenced", extract_json('here you go:\n```json\n{"a":1}\n```\nhope that helps') == {"a": 1})
check("prose wrapped array", extract_json('Sure! [\n{"x":2}\n]\nLet me know.') == [{"x": 2}])
check("trailing comma", extract_json('{"a":1,}') == {"a": 1})
check("garbage", extract_json("no json at all") is None)

print("\ncoerce_findings -- legacy shapes")
legacy = [{"Summary": "no slippage", "Vulnerability Details": {"Function Name": "harvest",
          "Description": "amountOutMin is 0"}, "Code Snippet": ["router.swap(a, 0, p);"],
          "Recommendation": "add minOut"}]
fs = coerce_findings(legacy, detector="d", file="f.sol")
check("legacy TitleCase keys parsed", len(fs) == 1 and fs[0].function_name == "harvest")
check("missing severity is recorded, not hidden", "severity" in fs[0].coerced_fields and fs[0].severity == "medium")
check("n8n output envelope", len(coerce_findings([{"output": legacy}])) == 1)
check("modern shape", len(coerce_findings({"findings": legacy})) == 1)
check("empty", coerce_findings([]) == [] and coerce_findings(None) == [])
check("critical maps to high", coerce_findings([{"summary": "x", "severity": "CRITICAL"}])[0].severity == "high")

print("\nslicing")
src = read_source(str(ROOT / "benchmark" / "cases" / "slippage_vuln_01.sol"))
small = slice_solidity(src, max_chars=99_000)
check("small file stays whole", len(small) == 1 and small[0].kind == "file")
big = slice_solidity(src, max_chars=1200, context_chars=600)
check("large file is sliced", len(big) > 1, f"got {len(big)}")
check("every slice carries the pragma", all("pragma solidity" in s.text for s in big))
check("slices are named after their enclosing contract/interface",
      all(s.name.split(".")[0] in {"IERC20", "IUniswapV2Router", "HarvestVault"} for s in big),
      [s.name for s in big])
check("harvest body lands in some slice", any("swapExactTokensForTokens(" in s.text and "pending," in s.text for s in big))
check("line offsets are sane", all(1 <= s.start_line <= s.end_line for s in big))
check("comment braces do not break matching", len(slice_solidity('contract A { // }\n function f() public { uint x; } }', max_chars=10)) >= 1)

print("\ngrounding")
idx = SourceIndex(src)
check("verbatim line found", idx.find("reward.approve(address(router), pending);") is not None)
check("reindented line still found", idx.find("reward.approve(   address(router),\n pending );") is not None)
check("invented line not found", idx.find("require(amountOut >= minOut, 'slippage');") is None)

real = Finding(summary="s", function_name="harvest", code_snippet=["reward.approve(address(router), pending);"])
fake = Finding(summary="s", function_name="harvest", code_snippet=["require(out >= minOut, 'slippage protection');"])
kept, dropped = apply_grounding([real, fake], src, drop_ungrounded=True)
check("real evidence survives", len(kept) == 1 and kept[0] is real)
check("hallucinated evidence dropped", len(dropped) == 1 and dropped[0] is fake)
check("surviving finding gets a line number", kept[0].line is not None, kept[0].line)

print("\ndedupe")
from bastet_plus.dedupe import merge_across_detectors, vote                 # noqa: E402
many = [Finding(summary="predictable randomness in drawWinner", detector=d, file="r.sol",
                function_name="drawWinner", description="seed from block.timestamp")
        for d in ["access_control__1", "owasp2025__0", "owasp2025__1", "owasp2025__7", "slippage__6"]]
expected_dets = {f.detector for f in many}   # _merge mutates the representative in place
merged = merge_across_detectors(many)
check("duplicates across detectors collapse to one", len(merged) == 1, len(merged))
check("merged provenance keeps every detector, not just the first three",
      set(merged[0].detector.split(",")) == expected_dets, merged[0].detector)

# Same bug, same function, near-identical summaries, but very different rationales:
# folding the rationale into the signature used to let these through as two findings.
twins = [
    Finding(summary="Reentrancy vulnerability in the withdraw function", detector="owasp2025__4",
            file="x.sol", function_name="withdraw",
            description="The balance is decremented after the external call, so a malicious "
                        "receiver can re-enter withdraw and drain the contract."),
    Finding(summary="Reentrancy vulnerability in the withdraw function", detector="owasp2025__9",
            file="x.sol", function_name="withdraw",
            description="State updates occur post-interaction; checks-effects-interactions is "
                        "violated and no guard modifier is applied to this entrypoint."),
]
check("same bug reported by two detectors collapses to one finding",
      len(merge_across_detectors(twins)) == 1, [f.summary for f in merge_across_detectors(twins)])

distinct = [
    Finding(summary="Reentrancy vulnerability in withdraw", detector="a", file="x.sol",
            function_name="withdraw", description="external call before state update"),
    Finding(summary="Missing slippage bound on the swap call", detector="b", file="x.sol",
            function_name="withdraw", description="amountOutMin passed as zero to the router"),
]
check("genuinely different bugs in the same function stay separate",
      len(merge_across_detectors(distinct)) == 2)

# The function name is settled by a separate gate, so it must not itself count
# as evidence that two findings describe the same bug.
short = [
    Finding(summary="Reentrancy vulnerability in the withdraw function", detector="a",
            file="x.sol", function_name="withdraw", description="state updated after the call"),
    Finding(summary="Unchecked external call in withdraw function", detector="b",
            file="x.sol", function_name="withdraw", description="return value of call is ignored"),
]
check("a shared function name alone does not merge two different bug classes",
      len(merge_across_detectors(short)) == 2,
      [f.summary for f in merge_across_detectors(short)])

a = Finding(summary="reentrancy in withdraw", detector="d", file="x.sol", function_name="withdraw", sample_idx=0)
b = Finding(summary="reentrancy in withdraw", detector="d", file="x.sol", function_name="withdraw", sample_idx=1)
c = Finding(summary="reentrancy in withdraw", detector="d", file="x.sol", function_name="withdraw", sample_idx=1)
kept, rej = vote([a, b, c], samples=3, threshold=0.5)
check("two distinct samples out of three survive a 0.5 threshold", len(kept) == 1 and kept[0].votes == 2)
solo = Finding(summary="flash loan risk in swap", detector="d", file="x.sol", function_name="swap", sample_idx=0)
kept2, rej2 = vote([a, solo], samples=3, threshold=0.5)
check("a one-sample-only finding is rejected", len(kept2) == 0 and len(rej2) == 2)

print("\nmetrics")
c = Confusion()
check("empty confusion does not divide by zero", c.precision == 0.0 and c.recall == 0.0 and c.f1 == 0.0)
c.tp, c.fp, c.fn, c.tn = 3, 1, 2, 4
check("precision", abs(c.precision - 0.75) < 1e-9)
check("recall", abs(c.recall - 0.6) < 1e-9)
check("fpr", abs(c.fpr - 0.2) < 1e-9)
lo, hi = wilson(3, 4)
check("wilson brackets the estimate", lo < 0.75 < hi, (lo, hi))

labels = {
    "classes": ["slippage", "reentrancy"],
    "detector_class": {"slippage__0": "slippage", "owasp2025__4": "reentrancy"},
    "cases": [
        {"file": "v.sol", "classes": ["slippage"], "functions": ["harvest"]},
        {"file": "s.sol", "classes": [], "functions": []},
    ],
}
res = {
    "v.sol": [Finding(summary="a", detector="slippage__0", function_name="harvest", file="v.sol", line=5)],
    "s.sol": [Finding(summary="b", detector="slippage__0", function_name="zapIn", file="s.sol")],
}
ev = evaluate(res, labels)
check("tp counted", ev.overall.tp == 1)
check("fp counted on the safe twin", ev.overall.fp == 1)
check("class the harness never raised is a tn, not a fn", ev.overall.tn == 2, ev.overall.as_dict())
check("localization credited", ev.localization_hits == 1)
check("clean-file noise counted", ev.clean_files == 1 and ev.findings_on_clean_files == 1)

# Wrong-class credit was the original eval's biggest scoring bug.
res2 = {"v.sol": [Finding(summary="a", detector="owasp2025__4", function_name="harvest", file="v.sol")],
        "s.sol": []}
ev2 = evaluate(res2, labels)
check("reentrancy hit does NOT satisfy a slippage label", ev2.overall.tp == 0 and ev2.overall.fn == 1)

print()
if FAILED:
    print(f"{len(FAILED)} FAILED: {FAILED}")
    raise SystemExit(1)
print("all offline tests passed")

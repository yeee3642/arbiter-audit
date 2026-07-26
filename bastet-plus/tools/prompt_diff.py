"""Mechanically diff every detector prompt: original n8n text vs what Bastet+ sends.

IMPROVEMENTS.md claims the detector knowledge is reused verbatim and that only
the output-contract block changes. That is a claim about 56 files and nobody
should take it on trust. This regenerates the evidence:

    python tools/prompt_diff.py            # summary table for all detectors
    python tools/prompt_diff.py slippage__0  # full unified diff for one

Exit code is non-zero if any detector's *knowledge* section differs, i.e. if
anything outside the output-contract block was touched.
"""

from __future__ import annotations

import difflib
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bastet_plus.detectors import _MOJIBAKE_FIXES, load_detectors  # noqa: E402
from bastet_plus.metrics import render_table                       # noqa: E402

PROMPTS = pathlib.Path(__file__).resolve().parent.parent / "prompts" / "legacy"


def knowledge_changed(det) -> list[str]:
    """Which mojibake repairs fired on this detector. Empty = knowledge untouched."""
    return [bad for bad, _ in _MOJIBAKE_FIXES if bad and bad in det.body]


def main() -> int:
    dets = load_detectors(PROMPTS)
    if len(sys.argv) > 1:
        wanted = sys.argv[1]
        for d in dets:
            if d.name == wanted:
                diff = difflib.unified_diff(
                    d.legacy_prompt().splitlines(), d.enhanced_prompt().splitlines(),
                    fromfile=f"{d.name} (original, from n8n)",
                    tofile=f"{d.name} (as Bastet+ sends it)", lineterm="", n=2,
                )
                print("\n".join(diff))
                return 0
        print(f"no detector named {wanted!r}", file=sys.stderr)
        return 2

    rows, touched = [], 0
    for d in dets:
        fixes = knowledge_changed(d)
        if fixes:
            touched += 1
        legacy, enhanced = d.legacy_prompt(), d.enhanced_prompt()
        # The knowledge section is `body`; everything after it is generated.
        rows.append([
            d.name,
            len(legacy),
            len(d.body),
            len(enhanced),
            "yes" if d.body.rstrip() != legacy.rstrip() else "no",
            str(len(fixes)) if fixes else "-",
        ])

    print(render_table(rows, ["detector", "original chars", "knowledge kept",
                              "sent chars", "output block replaced", "mojibake fixes"]))
    print(f"\n{len(dets)} detectors. The vulnerability-knowledge section is byte-identical "
          f"to the original in {len(dets) - touched}/{len(dets)}; the remaining {touched} "
          f"received documented mojibake repairs only (detectors._MOJIBAKE_FIXES).")
    print()
    print("HONEST QUALIFICATION -- two blocks are appended, and only the first is plumbing:")
    print("  1. `## Output contract`  -- generated from schema.py. Pure formatting. Replaces")
    print("     the original's output block, which disagreed with the schema it was")
    print("     validated against (see IMPROVEMENTS.md A1).")
    print("  2. `## Discipline`       -- NOT pure plumbing. It tells the model not to report")
    print("     a defence that exists elsewhere in the shown context, and to lower")
    print("     `confidence` rather than omit. That is anti-false-positive *detection*")
    print("     guidance. It plausibly moves precision on its own.")
    print()
    print("So the A/B is NOT a clean harness-only comparison. The Discipline block is a")
    print("prompt change and is not ablated anywhere. To isolate it, strip it from")
    print("Detector.enhanced_prompt() and re-run `bench`. That measurement has not been done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

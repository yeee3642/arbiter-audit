#!/usr/bin/env python3
"""Remove credentials from artefacts already on disk, idempotently.

`bastet_cc.redact` stops new secrets from being written. This applies the same
function to what is already committed -- one artefact
(`runs/probe/phase7_sustained_w32.json`) carried the gateway's key identifier
107 times, echoed back inside 429 error bodies.

Only context-anchored rules run (see `redact.py` for why shape-only scanning
corrupts an EVM corpus). `--audit` additionally reports shape-only matches
without touching them, so a human can look at the UniswapV2 init-code hashes and
confirm they are what they look like.

Scrubbing the working tree is necessary but not sufficient: the value stays in
git history and in every existing clone. The operational sequence is

  1. python scripts/scrub_artifacts.py --write
  2. rotate the AIS3 gateway token -- assume it is burned
  3. git filter-repo --replace-text <(echo '<value>==>[REDACTED]') && force-push
  4. git config core.hooksPath .githooks    # stops the next one

Steps 2 and 3 are the ones that matter; this only makes the working tree clean
so the rewrite has something correct to land on.

Run:  python scripts/scrub_artifacts.py [--write] [--audit]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bastet_cc.redact import redact, scan  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]

TARGET_GLOBS = ("runs/**/*.json", "runs/**/*.jsonl", "runs/**/*.csv")
SKIP_PARTS = {"figures"}


def targets() -> list[Path]:
    out: list[Path] = []
    for pattern in TARGET_GLOBS:
        for p in sorted(ROOT.glob(pattern)):
            if SKIP_PARTS & set(p.parts):
                continue
            out.append(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true",
                    help="rewrite files in place; default is a dry run")
    ap.add_argument("--audit", action="store_true",
                    help="also list shape-only matches (not rewritten)")
    args = ap.parse_args()

    dirty = 0
    advisory_total = 0
    for path in targets():
        original = path.read_text(encoding="utf-8", errors="replace")
        cleaned = redact(original)
        rel = path.relative_to(ROOT)

        if args.audit:
            advisory = {(n, s) for n, s, blocking in scan(original) if not blocking}
            if advisory:
                advisory_total += len(advisory)
                print(f"{rel}: {len(advisory)} shape-only match(es), NOT rewritten")
                for n, s in sorted(advisory)[:3]:
                    print(f"    {n}: {s}")

        if cleaned == original:
            continue
        dirty += 1
        blocking = {(n, s) for n, s, b in scan(original, advisory=False) if b}
        print(f"{rel}: {len(blocking)} credential(s)")
        for n, s in sorted(blocking)[:5]:
            print(f"    {n}: {s}")
        if args.write:
            path.write_text(cleaned, encoding="utf-8")
            print("    -> scrubbed")

    if args.audit and advisory_total:
        print(f"\n{advisory_total} shape-only match(es) left alone. On this corpus"
              " those are normally init-code hashes or TYPEHASHes -- confirm by eye.")

    if not dirty:
        print("\nclean: no context-anchored credentials in tracked artefacts")
        return 0
    if not args.write:
        print(f"\n{dirty} file(s) would change. Re-run with --write.")
        return 1
    print(f"\n{dirty} file(s) scrubbed. Now rotate the token and rewrite history --")
    print("the value is still in every existing clone until you do.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

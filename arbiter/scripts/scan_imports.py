#!/usr/bin/env python3
"""What does a real audit repository actually import?

The hermetic workspace compiled 0 of 24 contracts drawn from OneSavie's own dataset.
Before deciding what to vendor, count what is actually imported, so the dependency
cache is built from measurement rather than from guesswork.
"""

from __future__ import annotations

import collections
import csv
import os
import re
import sys

IMPORT = re.compile(r'import\s+(?:\{[^}]*\}\s*from\s*)?["\']([^"\']+)["\']')
SKIP_DIRS = {".git", "node_modules", "artifacts", "cache", "out", "typechain"}


def main() -> int:
    dataset = os.path.expanduser("~/Bastet/dataset")
    scored = os.path.expanduser("~/Bastet/evaluation_results.csv")

    repos = []
    with open(scored, encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            name = (row.get("file_name") or "").strip()
            if name and name not in repos:
                repos.append(name)

    prefixes: collections.Counter[str] = collections.Counter()
    per_repo: dict[str, collections.Counter[str]] = {}
    n_sol = 0

    for repo in repos:
        root = os.path.join(dataset, repo)
        local: collections.Counter[str] = collections.Counter()
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if not name.endswith(".sol"):
                    continue
                n_sol += 1
                path = os.path.join(dirpath, name)
                try:
                    text = open(path, encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                for spec in IMPORT.findall(text):
                    key = "<relative>" if spec.startswith(".") else "/".join(
                        spec.split("/")[:2]
                    )
                    prefixes[key] += 1
                    local[key] += 1
        per_repo[repo] = local

    print(f"repos={len(repos)}  sol_files={n_sol}")
    print()
    for key, count in prefixes.most_common(40):
        print(f"{count:6d}  {key}")
    print()
    print("per repo, non-relative prefixes:")
    for repo in repos:
        ext = {k: v for k, v in per_repo[repo].items() if k != "<relative>"}
        rel = per_repo[repo].get("<relative>", 0)
        print(f"  {repo[:36]:38s} rel={rel:4d}  {sorted(ext) if ext else '-'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

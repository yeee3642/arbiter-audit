"""Collapse the ablation runs into one table."""

import glob
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from bastet_plus.metrics import render_table  # noqa: E402

OUT = sys.argv[1] if len(sys.argv) > 1 else "benchmark_results"

ORDER = ["legacy", "full", "no_verify", "no_selfconsist", "no_grounding", "no_slicing"]
LABEL = {
    "legacy": "original harness",
    "full": "Bastet+ (all on)",
    "no_verify": "  - verification",
    "no_selfconsist": "  - self-consistency",
    "no_grounding": "  - evidence grounding",
    "no_slicing": "  - source slicing",
}

rows = []
found = {}
for path in glob.glob(os.path.join(OUT, "comparison_*.json")):
    doc = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    tag = os.path.basename(path).replace(".json", "").split("_")[-1]
    for arm, data in doc["arms"].items():
        key = "legacy" if arm == "legacy" else (tag if tag in ORDER else "full")
        found.setdefault(key, (data["metrics"], data["stats"]))

for key in ORDER:
    if key not in found:
        continue
    m, s = found[key]
    o = m["overall"]
    rows.append([
        LABEL[key],
        f"{o['precision']:.3f}", f"{o['recall']:.3f}", f"{o['f1']:.3f}",
        f"{o['false_positive_rate']:.3f}",
        str(m["total_findings_reported"]),
        f"{m['noise_per_clean_file']}",
        str(s.get("total_tokens", "-")),
    ])

print(render_table(rows, ["Configuration", "P", "R", "F1", "FPR",
                          "Findings", "Noise/clean file", "Tokens"]))

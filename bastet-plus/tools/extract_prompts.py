"""Extract LLM system prompts out of the original n8n workflow JSON files.

The prompts are the *detector knowledge* of Bastet. We lift them into plain
markdown so the legacy pipeline and the new pipeline can share byte-identical
detector text -- that is what makes the A/B comparison a harness comparison
rather than a prompt comparison.
"""

import json
import pathlib
import re
import sys

SRC = pathlib.Path(sys.argv[1])
DST = pathlib.Path(sys.argv[2])
DST.mkdir(parents=True, exist_ok=True)

index = {}

for wf in sorted(SRC.glob("*.json")):
    data = json.loads(wf.read_text(encoding="utf-8"))
    prompts = []
    model = None
    for node in data.get("nodes", []):
        ntype = node.get("type", "")
        params = node.get("parameters", {}) or {}
        if ntype.endswith("lmChatOpenAi"):
            m = params.get("model")
            if isinstance(m, dict):
                model = m.get("value")
            elif isinstance(m, str):
                model = m
        mv = (params.get("messages") or {}).get("messageValues")
        if mv:
            for entry in mv:
                msg = entry.get("message")
                if isinstance(msg, str) and len(msg) > 200:
                    prompts.append((node.get("name", "?"), msg))
        # agent nodes stash the prompt in options.systemMessage
        sysmsg = (params.get("options") or {}).get("systemMessage")
        if isinstance(sysmsg, str) and len(sysmsg) > 200:
            prompts.append((node.get("name", "?"), sysmsg))

    if not prompts:
        print(f"  !! no prompt found in {wf.name}")
        continue

    for i, (node_name, text) in enumerate(prompts):
        # n8n stores expressions with a leading '='
        if text.startswith("="):
            text = text[1:]
        slug = wf.stem if len(prompts) == 1 else f"{wf.stem}__{i}"
        out = DST / f"{slug}.md"
        out.write_text(text, encoding="utf-8")
        index[slug] = {
            "workflow": wf.name,
            "node": node_name,
            "model": model,
            "chars": len(text),
            "mojibake": len(re.findall(r"[?][a-z ]|�", text)),
        }
        print(f"  {slug:34} node={node_name:34} model={model} chars={len(text)}")

(DST / "_index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
print(f"\nwrote {len(index)} prompts to {DST}")

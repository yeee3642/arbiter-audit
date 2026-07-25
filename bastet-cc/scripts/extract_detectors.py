#!/usr/bin/env python3
"""Extract every LLM detector out of Bastet's n8n workflow JSON into standalone markdown.

Upstream Bastet keeps its entire detection IP -- 56 hand-written chain-of-thought
prompts -- locked inside n8n workflow definitions. Nothing can read them but n8n.
This lifts each `chainLlm` node into a plain markdown file with YAML frontmatter so
the prompts become portable: usable by any backend, diffable in git, and editable
without booting a workflow engine.

Usage:
    python scripts/extract_detectors.py ../upstream-bastet/n8n_workflow detectors/
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

CHAIN_LLM = "@n8n/n8n-nodes-langchain.chainLlm"
OUTPUT_PARSER = "@n8n/n8n-nodes-langchain.outputParserStructured"
LM_CHAT = "@n8n/n8n-nodes-langchain.lmChatOpenAi"

# Bastet's 56 detectors carry no tag metadata; they are grouped only by which
# workflow file they live in. Map each workflow to the Bastet taxonomy tags it
# targets so routing and per-tag scoring have something to key on. Derived by
# reading each workflow's node names against "Tag Definitions.md".
WORKFLOW_TAGS = {
    "slippage": ["Slippage"],
    "slippage_min_amount": ["Slippage"],
    "access_control": ["Access Control"],
    "chainlink": ["Chainlink", "Oracle", "Bad Randomness"],
    "erc4626": ["ERC4626"],
    "flashloan": ["Flashloan"],
    "denial_of_service": ["DoS"],
    "owasp2025": [
        "Access Control", "Oracle", "Logic error", "Input Validation",
        "Reentrancy", "call / delegatecall", "Flashloan", "Arithmetic",
        "Bad Randomness", "DoS",
    ],
    "4naly3er": [
        "Logic error", "Arithmetic", "Access Control", "ERC20",
        "ERC721", "Oracle", "call / delegatecall", "Flashloan",
    ],
}

# Node names in owasp2025/4naly3er encode their own target tag; prefer those.
NODE_TAG_HINTS = [
    (r"Improper Access Control|avoidTx\.origin|centralizationRisk", "Access Control"),
    (r"Price Oracle Manipulation|wstETHPriceStEth", "Oracle"),
    (r"Logic Errors|comparisonOutsideCondition|msg\.valueInLoop", "Logic error"),
    (r"Lack of Input Validation", "Input Validation"),
    (r"Reentrancy", "Reentrancy"),
    (r"Unchecked External Calls|delegateCallInLoop", "call / delegatecall"),
    (r"Flash Loan|get_dy_underlyingFlashLoan", "Flashloan"),
    (r"Integer Overflow|blockNumberL", "Arithmetic"),
    (r"Insecure Randomness", "Bad Randomness"),
    (r"Denial Of Service", "DoS"),
    (r"FoTTokens|approve0first", "ERC20"),
    (r"ERC721usage|NFTRedefinesMint", "ERC721"),
]


def slugify(name: str) -> str:
    s = re.sub(r"[^\w\s-]", "", name).strip().lower()
    return re.sub(r"[\s_-]+", "_", s)


def infer_tags(node_name: str, workflow: str) -> list[str]:
    for pattern, tag in NODE_TAG_HINTS:
        if re.search(pattern, node_name, re.I):
            return [tag]
    return WORKFLOW_TAGS.get(workflow, [])


def system_message(node: dict) -> str:
    """Pull the CoT prompt out of a chainLlm node's messageValues."""
    values = node.get("parameters", {}).get("messages", {}).get("messageValues", [])
    parts = [v.get("message", "") for v in values if v.get("message")]
    text = "\n\n".join(parts)
    # n8n prefixes expression-enabled fields with '='; strip it.
    return text[1:] if text.startswith("=") else text


def scan_for_routing_hints(prompt: str) -> list[str]:
    """Mine the prompt for Solidity identifiers that reveal what code it cares about.

    These become the seed conditions for the deterministic routing layer -- a
    detector that never mentions `swap` has no business reading a swap-free file.
    """
    hints: set[str] = set()
    # Solidity-looking identifiers: calls, well-known function names, modifiers.
    for m in re.finditer(r"\b([a-z_][A-Za-z0-9_]{3,})\s*\(", prompt):
        hints.add(m.group(1))
    for m in re.finditer(r"\b(onlyOwner|nonReentrant|msg\.sender|tx\.origin|"
                         r"block\.(?:timestamp|number)|delegatecall|staticcall)\b", prompt):
        hints.add(m.group(1))
    noise = {
        "function", "return", "returns", "require", "assert", "revert", "this",
        "example", "note", "e.g", "i.e", "etc", "conclusion", "thought", "step",
        "following", "above", "below", "check", "checks", "value", "values",
    }
    return sorted(h for h in hints if h.lower() not in noise)


def main(src_dir: str, out_dir: str) -> int:
    src, out = Path(src_dir), Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    index: list[dict] = []
    failures: list[str] = []

    for wf_path in sorted(src.glob("*.json")):
        workflow = wf_path.stem
        try:
            doc = json.loads(wf_path.read_text())
        except json.JSONDecodeError as exc:
            failures.append(f"{wf_path.name}: {exc}")
            continue

        nodes = doc.get("nodes", [])
        # The output schema is shared by every detector in a workflow.
        schema = next(
            (n["parameters"].get("inputSchema", "")
             for n in nodes if n.get("type") == OUTPUT_PARSER),
            "",
        )
        model = next(
            (n["parameters"].get("model", {}).get("value", "")
             for n in nodes if n.get("type") == LM_CHAT),
            "",
        )

        for node in nodes:
            if node.get("type") != CHAIN_LLM:
                continue
            name = node["name"]
            prompt = system_message(node)
            if not prompt:
                failures.append(f"{workflow}/{name}: empty prompt")
                continue

            tags = infer_tags(name, workflow)
            hints = scan_for_routing_hints(prompt)
            slug = f"{workflow}__{slugify(name)}"

            frontmatter = [
                "---",
                f"id: {slug}",
                f"name: {json.dumps(name)}",
                f"source_workflow: {workflow}",
                f"upstream_model: {model or 'unspecified'}",
                f"tags: {json.dumps(tags)}",
                f"routing_hints: {json.dumps(hints)}",
                f"prompt_chars: {len(prompt)}",
                "---",
                "",
            ]
            body = [
                f"# {name}",
                "",
                "## Detection prompt",
                "",
                prompt,
                "",
            ]
            if schema:
                body += ["## Output schema", "", "```json", schema, "```", ""]

            (out / f"{slug}.md").write_text("\n".join(frontmatter + body))
            index.append({
                "id": slug,
                "name": name,
                "source_workflow": workflow,
                "tags": tags,
                "routing_hints": hints,
                "prompt_chars": len(prompt),
            })

    (out / "index.json").write_text(json.dumps(index, indent=2, ensure_ascii=False))

    covered = sorted({t for d in index for t in d["tags"]})
    print(f"extracted {len(index)} detectors from {len(list(src.glob('*.json')))} workflows")
    print(f"total prompt chars: {sum(d['prompt_chars'] for d in index):,}")
    print(f"tags covered: {len(covered)}")
    for t in covered:
        n = sum(1 for d in index if t in d["tags"])
        print(f"  {t:<24} {n:>3} detector(s)")
    if failures:
        print(f"\n{len(failures)} failure(s):")
        for f in failures:
            print(f"  {f}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))

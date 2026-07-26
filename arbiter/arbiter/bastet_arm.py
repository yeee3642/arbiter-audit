"""Arm A: Bastet, reproduced verbatim, running through our gateway and our scorer.

Fidelity is the whole value of this file, so what is and is not preserved is stated
explicitly rather than left to be inferred:

  * the system message is the n8n ``chainLlm`` node's ``messageValues[0].message``,
    extracted from the workflow JSON with no edit of any kind;
  * the user message is the contract source followed by n8n's own format instructions,
    with ``{{`` restored to ``{`` exactly as n8n renders them;
  * ``temperature`` is not sent, because the workflows' llm options are ``{}``;
  * the decision rule is Bastet's own, from ``cli/commands/evaluate/eval.py``:
    a sample is positive iff any detector returns a non-empty ``output`` list;
  * the three gas-optimisation detectors are excluded, leaving 53. Gas findings are not
    vulnerabilities, and counting them would manufacture false positives that Bastet
    never intended to claim. This is a concession in Bastet's favour, per fairness
    clause 4.

Sharing ``Gateway`` with ARBITER is deliberate. Rate limiting, cost accounting from
response headers, model read-back, and recovery of ``content: null`` responses from the
reasoning field are then not merely matched between the arms, they are the same code
path. Neither arm can discharge a fairness obligation differently from the other because
neither arm implements one.

Request cost: 53 per sample, against ARBITER's ceiling of 16. The baseline is given the
larger budget, and fairness clause 3's equal-request control is therefore not owed --
it protects the baseline against a challenger that buys accuracy with extra sampling,
and here the challenger is the cheaper arm.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .gateway import Gateway, RateLimiter


def load_detectors(prompts_dir: Path, include_gas: bool = False) -> list[dict[str, str]]:
    index = json.loads((prompts_dir / "index.json").read_text(encoding="utf-8"))
    entries = index if isinstance(index, list) else list(index.values())
    if not include_gas:
        entries = [d for d in entries if "GAS" not in d["detector_node_name"]]
    return entries


def load_format_instructions(prompts_dir: Path) -> str:
    raw = (prompts_dir / "n8n_format_instructions.txt").read_text(encoding="utf-8")
    # n8n renders doubled braces as single ones before the prompt reaches the model.
    return raw.replace("{{", "{").replace("}}", "}")


def parse_output(text: str | None) -> tuple[list[Any] | None, str]:
    """Bastet's reply shape, parsed as leniently as we can manage.

    Leniency here is a fairness obligation, not a courtesy: every reply we fail to parse
    would otherwise become a false negative for the baseline, and winning that way would
    be winning on output handling rather than on detection. The fallbacks accept a
    fenced block, an object anywhere in the text, a null output, and a bare array,
    because Bastet's own prompts permit the last of these.
    """
    if not text:
        return None, "empty"
    stripped = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()

    candidates: list[str] = []
    for match in re.finditer(r"\{", stripped):
        depth = 0
        for i in range(match.start(), len(stripped)):
            if stripped[i] == "{":
                depth += 1
            elif stripped[i] == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(stripped[match.start() : i + 1])
                    break
        if len(candidates) > 40:
            break

    for candidate in sorted(candidates, key=len, reverse=True):
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "output" in obj:
            value = obj["output"]
            if isinstance(value, list):
                return value, "ok"
            if value is None:
                return [], "ok"

    try:
        obj = json.loads(stripped)
        if isinstance(obj, list):
            return obj, "ok_bare_array"
    except json.JSONDecodeError:
        pass
    return None, "parse_fail"


def run_bastet(
    *,
    evalset: Path,
    prompts_dir: Path,
    model: str,
    run_id: str,
    out_dir: Path,
    repeats: int = 1,
    concurrency: int = 12,
    max_tokens: int = 4096,
    rpm: int = 110,
    api_key: str | None = None,
) -> dict[str, Any]:
    data = json.loads(evalset.read_text(encoding="utf-8"))
    items = data["items"]
    detectors = load_detectors(prompts_dir)
    fmt = load_format_instructions(prompts_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    gateway = Gateway(
        model=model,
        api_key=api_key,
        limiter=RateLimiter(rpm),
        ledger_path=out_dir / f"{run_id}.ledger.jsonl",
    )

    jobs_path = out_dir / f"{run_id}.jobs.jsonl"
    done: set[tuple[int, str, str]] = set()
    if jobs_path.exists():
        for line in jobs_path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            done.add((row["repeat"], row["sample"], row["detector"]))

    write_lock = threading.Lock()
    started = time.monotonic()

    def work(repeat: int, sample: dict[str, Any], det: dict[str, str]) -> None:
        key = (repeat, sample["id"], det["detector_node_name"])
        if key in done:
            return
        user = (sample.get("code") or "") + "\n" + fmt
        messages = [
            {"role": "system", "content": det["system_prompt"]},
            {"role": "user", "content": user},
        ]
        status = "error"
        findings: list[Any] | None = None
        text = ""
        try:
            message = gateway.chat(
                messages,
                max_tokens=max_tokens,
                temperature=0.0,
                tag=f"bastet:{sample['id']}:{det['detector_node_name']}",
            )
            text = message.get("content") or ""
            findings, status = parse_output(text)
            if status == "parse_fail":
                # One retry, counted separately, per fairness clause 1.
                message = gateway.chat(
                    messages,
                    max_tokens=max_tokens,
                    temperature=0.0,
                    tag=f"bastet:{sample['id']}:{det['detector_node_name']}:retry",
                )
                text = message.get("content") or ""
                findings, status = parse_output(text)
                if status == "parse_fail":
                    gateway.note_parse_failure()
        except Exception as exc:  # noqa: BLE001
            status = f"error:{type(exc).__name__}"

        row = {
            "repeat": repeat,
            "sample": sample["id"],
            "label": sample.get("label"),
            "detector": det["detector_node_name"],
            "status": status,
            "n_findings": len(findings) if isinstance(findings, list) else None,
            "raw_head": text[:300],
        }
        with write_lock:
            with jobs_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    jobs = [
        (r, sample, det)
        for r in range(repeats)
        for sample in items
        for det in detectors
    ]
    todo = [j for j in jobs if (j[0], j[1]["id"], j[2]["detector_node_name"]) not in done]
    print(
        f"BASTET (arm A)  model={model}  samples={len(items)}  detectors={len(detectors)}"
        f"  repeats={repeats}  requests={len(todo)}  done={len(done)}",
        flush=True,
    )

    completed = 0
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(work, *j) for j in todo]
        for future in as_completed(futures):
            future.result()
            completed += 1
            if completed % 50 == 0 or completed == len(todo):
                print(
                    f"  {completed}/{len(todo)}  requests={gateway.usage.requests}  "
                    f"parse_fail={gateway.usage.parse_failures}  "
                    f"${gateway.usage.cost_usd:.4f}  "
                    f"{time.monotonic() - started:.0f}s",
                    flush=True,
                )

    rows = [
        json.loads(line)
        for line in jobs_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    predictions = _decide(rows, repeats)
    summary = {
        "arm": "bastet_verbatim",
        "run_id": run_id,
        "model": model,
        "evalset": str(evalset),
        "evalset_meta": data.get("meta", {}),
        "repeats": repeats,
        "max_tokens": max_tokens,
        "n_detectors": len(detectors),
        "decision_rule": "Bastet eval.py: positive iff any detector output != []",
        "requests_per_sample": len(detectors),
        "wall_clock_s": round(time.monotonic() - started, 1),
        "usage": gateway.usage.as_dict(),
        "predictions_by_repeat": predictions,
        "detector_fire_rates": _fire_rates(rows, items),
    }
    (out_dir / f"{run_id}.summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    return summary


def _decide(rows: list[dict[str, Any]], repeats: int) -> dict[str, dict[str, str]]:
    """Bastet's decision rule, applied per repeat."""
    out: dict[str, dict[str, str]] = {str(r): {} for r in range(repeats)}
    grouped: dict[tuple[int, str], list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault((row["repeat"], row["sample"]), []).append(row)
    for (repeat, sample), group in grouped.items():
        fired = any(bool(g["n_findings"]) for g in group)
        out.setdefault(str(repeat), {})[sample] = "vuln" if fired else "safe"
    return out


def _fire_rates(
    rows: list[dict[str, Any]], items: list[dict[str, Any]]
) -> dict[str, dict[str, float]]:
    """Per-detector firing rate on vulnerable versus safe samples.

    The difference is the detector's discriminative power. A detector that fires as
    often on patched code as on vulnerable code contributes nothing but false positives,
    and the previous measurement found 25 of 53 at or below zero.
    """
    labels = {i["id"]: i.get("label") for i in items}
    stats: dict[str, dict[str, list[int]]] = {}
    for row in rows:
        label = labels.get(row["sample"])
        if label not in ("vuln", "safe"):
            continue
        bucket = stats.setdefault(row["detector"], {"vuln": [], "safe": []})
        bucket[label].append(1 if row["n_findings"] else 0)
    out: dict[str, dict[str, float]] = {}
    for detector, bucket in stats.items():
        on_vuln = sum(bucket["vuln"]) / len(bucket["vuln"]) if bucket["vuln"] else 0.0
        on_safe = sum(bucket["safe"]) / len(bucket["safe"]) if bucket["safe"] else 0.0
        out[detector] = {
            "fires_on_vuln": round(on_vuln, 3),
            "fires_on_safe": round(on_safe, 3),
            "discrimination": round(on_vuln - on_safe, 3),
        }
    return dict(sorted(out.items(), key=lambda kv: -kv[1]["discrimination"]))

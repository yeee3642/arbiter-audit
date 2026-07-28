"""Adjudication: judge what was found, never what is looked for.

The measured reason this exists. Running the strict predicates inside the generator
found five true positives the permissive set never found and lost ten -- a filter cannot
do that, so the predicates were steering the agent's search and not merely policing its
output. Gates that can only ever reject belong after generation.

So a cascade runs the generator more than once, under different predicate sets, unions
everything either pass proved, and only then puts each accepted exploit back through the
gates as they stand. Breadth comes from generation; soundness comes from adjudication;
neither is spending the other's budget.
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .workspace import Workspace

WS = Path("/tmp/arbiter-adjudicate")


def _fragments(row: dict[str, Any]) -> list[dict[str, Any]]:
    """The run_exploit arguments the agent supplied, recovered from its own turn trace."""
    out: list[dict[str, Any]] = []
    for turn in row.get("trace") or []:
        for call in turn.get("tool_calls") or []:
            if call.get("name") != "run_exploit":
                continue
            try:
                out.append(json.loads(call.get("arguments") or ""))
            except (json.JSONDecodeError, TypeError):
                continue
    return out


def _judge(job: tuple[str, str, str, list[dict[str, Any]]]) -> dict[str, Any]:
    sample_id, truth, source, arg_list = job
    rec: dict[str, Any] = {"sample_id": sample_id, "truth": truth}
    if not source or not arg_list:
        rec["verdict"] = "no fragments"
        return rec

    ws = Workspace(WS, sample_id[:70], source)
    try:
        for i, args in enumerate(arg_list):
            predicate = str(args.get("predicate") or "")
            mode = str(args.get("mode") or ("eoa" if args.get("attack_body") else "contract"))
            try:
                if predicate == "victim_loss":
                    solidity = ws.compose_victim_loss(
                        deploy_code=str(args.get("deploy_code") or ""),
                        victim_enter=str(args.get("victim_enter") or ""),
                        victim_exit=str(args.get("victim_exit") or ""),
                        attacker_code=str(args.get("attacker_code") or ""),
                        attack_body=str(args.get("attack_body") or ""),
                        mode=mode,
                        token_expr=str(args.get("token_expr") or ""),
                    )
                else:
                    solidity = ws.compose_exploit(
                        deploy_code=str(args.get("deploy_code") or ""),
                        attacker_code=str(args.get("attacker_code") or ""),
                        predicate=predicate or "eth_profit",
                        observed_getter=str(args.get("observed_getter") or ""),
                        token_expr=str(args.get("token_expr") or ""),
                        liveness_call=str(args.get("liveness_call") or ""),
                        attack_body=str(args.get("attack_body") or ""),
                        honest_body=str(args.get("honest_body") or ""),
                        mode=mode,
                    )
            except ValueError:
                continue          # the gates refused it at composition
            name = ws.write_poc(f"Adj{i}", solidity)
            if not ws.build().ok:
                continue
            run = ws.run_poc(name)
            if not any(l.strip().startswith("[PASS]") for l in run.combined.splitlines()):
                continue
            # Survived the predicate; it must also fail with the attack removed, or
            # something other than the attack satisfied it.
            neutered, found = ws.neuter(solidity)
            if found:
                ws.write_poc(f"Adj{i}Neg", neutered)
                if ws.build().ok and any(
                    l.strip().startswith("[PASS]")
                    for l in ws.run_poc(f"Adj{i}NegPoc").combined.splitlines()
                ):
                    continue     # passes without the attack; not evidence
            rec.update({"verdict": "accepted", "predicate": predicate,
                        "solidity": solidity})
            return rec
    except Exception as exc:  # noqa: BLE001
        rec["verdict"] = f"error: {type(exc).__name__}"
        return rec
    finally:
        ws.cleanup()
    rec["verdict"] = "refused"
    return rec


def adjudicate(result_paths: list[Path], out_path: Path,
               workers: int | None = None) -> dict[str, Any]:
    """Union every pass's accepted findings, then re-judge each under the current gates."""
    rows: dict[str, dict[str, Any]] = {}
    per_pass: dict[str, list[str]] = {}
    for path in result_paths:
        flagged: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            rows.setdefault(row["sample_id"], row)
            if row.get("predicted") == "vuln":
                flagged.append(row["sample_id"])
                rows[row["sample_id"]] = row      # prefer a pass that found something
        per_pass[path.stem] = flagged

    union = sorted({s for ids in per_pass.values() for s in ids})
    jobs = [
        (s, rows[s].get("truth", "unknown"), rows[s].get("source", ""),
         _fragments(rows[s]))
        for s in union
    ]
    workers = workers or max(2, (os.cpu_count() or 4) - 4)
    judged: list[dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for fut in as_completed([pool.submit(_judge, j) for j in jobs]):
            judged.append(fut.result())

    out_path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in judged), encoding="utf-8"
    )
    return {
        "passes": {k: len(v) for k, v in per_pass.items()},
        "union": len(union),
        "accepted": sorted(r["sample_id"] for r in judged if r["verdict"] == "accepted"),
        "refused": sorted(r["sample_id"] for r in judged if r["verdict"] != "accepted"),
        "detail": judged,
        "all_samples": sorted(rows),
    }


def render_cascade(report: dict[str, Any], truth: dict[str, str]) -> str:
    """Score the union and the adjudicated union side by side, with every cell shown."""
    def score(flagged: set[str]) -> tuple[int, int, int, int]:
        tp = sum(1 for s, t in truth.items() if t == "vuln" and s in flagged)
        fp = sum(1 for s, t in truth.items() if t == "safe" and s in flagged)
        fn = sum(1 for s, t in truth.items() if t == "vuln" and s not in flagged)
        tn = sum(1 for s, t in truth.items() if t == "safe" and s not in flagged)
        return tp, tn, fp, fn

    def rates(tp: int, tn: int, fp: int, fn: int) -> str:
        n = tp + tn + fp + fn
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        den = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
        mcc = ((tp * tn - fp * fn) / den) if den else 0.0
        return (f"{tp:>4d} {tn:>4d} {fp:>4d} {fn:>4d}   {prec:>6.3f} {rec:>6.3f} "
                f"{f1:>6.3f} {mcc:>6.3f}   ({(tp + tn) / n if n else 0:.3f} acc)")

    union = {s for ids in [report["accepted"], report["refused"]] for s in ids}
    lines = [
        f"{'':28s} {'TP':>4s} {'TN':>4s} {'FP':>4s} {'FN':>4s}   "
        f"{'prec':>6s} {'rec':>6s} {'f1':>6s} {'mcc':>6s}",
        f"{'union, ungated':28s} {rates(*score(union))}",
        f"{'union, adjudicated':28s} {rates(*score(set(report['accepted'])))}",
        "",
        "per pass, findings offered: " + ", ".join(
            f"{k}={v}" for k, v in report["passes"].items()
        ),
        f"union {report['union']} -> {len(report['accepted'])} accepted, "
        f"{len(report['refused'])} refused by the gates",
    ]
    return "\n".join(lines)

#!/usr/bin/env python3
"""Probe the AIS3 LLM endpoint to pin down ais3/nemotron-3-ultra-550b behaviour.

Everything here is *measured*, never assumed.  Each phase writes a JSON blob
into runs/probe/ so that later modules can re-read the raw evidence.

Usage:
    python scripts/probe_model.py all
    python scripts/probe_model.py schema|dump|throughput|concurrency|refusal|truncate
"""
from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from openai import OpenAI

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bastet_cc.redact import redact_error  # noqa: E402

BASE_URL = os.environ.get("AIS3_BASE_URL", "https://llm-api.zoolab.org/v1")
API_KEY = os.environ.get("AIS3_API_KEY") or sys.exit("set AIS3_API_KEY")
MODEL = os.environ.get("AIS3_MODEL", "ais3/nemotron-3-ultra-550b")

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "runs" / "probe"
OUT.mkdir(parents=True, exist_ok=True)

client = OpenAI(base_url=BASE_URL, api_key=API_KEY, timeout=600.0, max_retries=0)

# --------------------------------------------------------------------------
# The upstream Bastet output schema.  Top level is an ARRAY, but json_schema
# mode on most OpenAI-compatible servers requires a top-level OBJECT, so we
# wrap it in {"findings": [...]}.
# --------------------------------------------------------------------------
FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "severity": {"type": "string", "enum": ["high", "medium", "low"]},
        "vulnerability_details": {
            "type": "object",
            "properties": {
                "function_name": {"type": "string"},
                "description": {"type": "string"},
            },
            "required": ["function_name", "description"],
            "additionalProperties": False,
        },
        "code_snippet": {"type": "array", "items": {"type": "string"}},
        "recommendation": {"type": "string"},
    },
    "required": [
        "summary",
        "severity",
        "vulnerability_details",
        "code_snippet",
        "recommendation",
    ],
    "additionalProperties": False,
}

WRAPPED_SCHEMA = {
    "type": "object",
    "properties": {"findings": {"type": "array", "items": FINDING_SCHEMA}},
    "required": ["findings"],
    "additionalProperties": False,
}

RESPONSE_FORMAT_JSON_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "bastet_findings",
        "strict": True,
        "schema": WRAPPED_SCHEMA,
    },
}

# --------------------------------------------------------------------------
# Real code slice: Pool2SingleAssetCompounder.harvest() from the test set.
# swapExactTokensForTokens(amount, 0, ...) -> textbook missing-slippage bug.
# --------------------------------------------------------------------------
SLICE_PATH = (
    "/home/e0pwr/ais3-2026/data/ex/test/e0d2d83ea351/"
    "src/vault/strategy/Pool2SingleAssetCompounder.sol"
)
SLICE_START, SLICE_END = 44, 66


def load_slice() -> str:
    lines = Path(SLICE_PATH).read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[SLICE_START - 1 : SLICE_END])


def detector_prompt(name: str) -> str:
    """Extract the '## Detection prompt' body from a detector markdown file."""
    txt = (ROOT / "detectors" / name).read_text(encoding="utf-8")
    body = txt.split("---", 2)[2] if txt.startswith("---") else txt
    m = re.search(r"## Detection prompt\n(.*?)\n## Output schema", body, re.S)
    if not m:
        m = re.search(r"## Detection prompt\n(.*)", body, re.S)
    return m.group(1).strip()


SLIPPAGE_DET = "slippage_min_amount__cot_slippage_min_amount.md"


def user_block(code: str, path: str = "Pool2SingleAssetCompounder.sol") -> str:
    return f"File: {path}\n\n```solidity\n{code}\n```"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
@dataclass
class Call:
    ok: bool
    latency: float
    content: str | None = None
    reasoning: str | None = None
    finish_reason: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    error: str | None = None
    raw: dict[str, Any] | None = None


def chat(messages, *, max_tokens=4096, temperature=0.0, response_format=None,
         keep_raw=False, extra=None) -> Call:
    kw: dict[str, Any] = dict(
        model=MODEL, messages=messages, max_tokens=max_tokens, temperature=temperature
    )
    if response_format is not None:
        kw["response_format"] = response_format
    if extra:
        kw.update(extra)
    t0 = time.perf_counter()
    try:
        r = client.chat.completions.create(**kw)
    except Exception as e:  # noqa: BLE001
        # The gateway echoes the caller's key identifier inside 429 bodies, and
        # these strings are persisted verbatim into runs/probe/*.json. Redact at
        # the point of capture -- a .gitignore cannot see inside a value.
        return Call(False, time.perf_counter() - t0,
                    error=redact_error(f"{type(e).__name__}: {str(e)[:400]}"))
    dt = time.perf_counter() - t0
    ch = r.choices[0]
    msg = ch.message
    reasoning = getattr(msg, "reasoning_content", None) or getattr(msg, "reasoning", None)
    return Call(
        ok=True,
        latency=dt,
        content=msg.content,
        reasoning=reasoning,
        finish_reason=ch.finish_reason,
        prompt_tokens=r.usage.prompt_tokens if r.usage else None,
        completion_tokens=r.usage.completion_tokens if r.usage else None,
        raw=r.model_dump() if keep_raw else None,
    )


FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def extract_json(text: str | None):
    """Best-effort recovery of the JSON payload from free-form model output."""
    if not text:
        return None, "empty-content"
    t = text.strip()
    for cand in [t] + [m.strip() for m in FENCE.findall(t)]:
        try:
            return json.loads(cand), None
        except Exception:  # noqa: BLE001
            pass
    # last resort: first balanced [...] or {...}
    for open_c, close_c in (("[", "]"), ("{", "}")):
        i = t.find(open_c)
        j = t.rfind(close_c)
        if i != -1 and j > i:
            try:
                return json.loads(t[i : j + 1]), "salvaged-substring"
            except Exception:  # noqa: BLE001
                pass
    return None, "unparseable"


def normalize(obj):
    """Upstream shape is a list; wrapped mode gives {'findings': [...]}."""
    if isinstance(obj, dict) and "findings" in obj:
        obj = obj["findings"]
    if isinstance(obj, dict):
        obj = [obj]
    return obj


REQUIRED = {"summary", "severity", "vulnerability_details", "code_snippet", "recommendation"}


def schema_valid(obj) -> tuple[bool, str]:
    arr = normalize(obj)
    if not isinstance(arr, list):
        return False, "not-a-list"
    for it in arr:
        if not isinstance(it, dict):
            return False, "item-not-object"
        missing = REQUIRED - set(it)
        if missing:
            return False, f"missing:{sorted(missing)}"
        if it["severity"] not in ("high", "medium", "low"):
            return False, f"bad-severity:{it['severity']!r}"
        vd = it["vulnerability_details"]
        if not isinstance(vd, dict) or {"function_name", "description"} - set(vd):
            return False, "bad-vulnerability_details"
        if not isinstance(it["code_snippet"], list):
            return False, "code_snippet-not-list"
    return True, "ok"


def dump(name: str, payload) -> Path:
    p = OUT / f"{name}.json"
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  -> wrote {p}")
    return p


def stats(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return {}
    return {
        "n": len(xs),
        "min": round(min(xs), 3),
        "p50": round(statistics.median(xs), 3),
        "mean": round(statistics.fmean(xs), 3),
        "max": round(max(xs), 3),
        "stdev": round(statistics.stdev(xs), 3) if len(xs) > 1 else 0.0,
    }


JSON_TEXT_SUFFIX = (
    "\n\nRespond with ONLY a JSON array matching this schema, no prose, no markdown "
    "fences:\n"
    '[{"summary": str, "severity": "high"|"medium"|"low", '
    '"vulnerability_details": {"function_name": str, "description": str}, '
    '"code_snippet": [str], "recommendation": str}]\n'
    "If there is no vulnerability, respond with exactly []."
)


# ==========================================================================
# Phase 1: structured output modes
# ==========================================================================
def phase_schema(trials=5):
    print("\n=== PHASE 1: structured output modes ===")
    sysmsg = detector_prompt(SLIPPAGE_DET)
    code = load_slice()
    modes = {
        "json_schema_strict": dict(
            response_format=RESPONSE_FORMAT_JSON_SCHEMA,
            suffix="\n\nReturn the findings under the key \"findings\".",
        ),
        "json_object": dict(
            response_format={"type": "json_object"},
            suffix="\n\nReturn a JSON object of the form {\"findings\": [ ... ]} "
                   "where each finding has summary, severity, vulnerability_details "
                   "{function_name, description}, code_snippet (array of strings), "
                   "recommendation.",
        ),
        "plain_text": dict(response_format=None, suffix=JSON_TEXT_SUFFIX),
    }
    results = {}
    for mode, cfg in modes.items():
        rows = []
        for i in range(trials):
            msgs = [
                {"role": "system", "content": sysmsg + cfg["suffix"]},
                {"role": "user", "content": user_block(code)},
            ]
            c = chat(msgs, max_tokens=4096, response_format=cfg["response_format"])
            row = {
                "trial": i,
                "api_ok": c.ok,
                "error": c.error,
                "latency_s": round(c.latency, 2),
                "finish_reason": c.finish_reason,
                "content_is_none": c.content is None,
                "content_len": len(c.content) if c.content else 0,
                "has_reasoning_field": c.reasoning is not None,
                "prompt_tokens": c.prompt_tokens,
                "completion_tokens": c.completion_tokens,
            }
            if c.ok:
                obj, perr = extract_json(c.content)
                row["parse_error"] = perr
                if obj is not None:
                    ok, why = schema_valid(obj)
                    row["schema_ok"] = ok
                    row["schema_why"] = why
                    row["n_findings"] = len(normalize(obj)) if isinstance(normalize(obj), list) else None
                else:
                    row["schema_ok"] = False
                    row["schema_why"] = perr
                row["raw_head"] = (c.content or "")[:400]
            else:
                row["schema_ok"] = False
                row["schema_why"] = "api-error"
            rows.append(row)
            usable = row["schema_ok"]
            print(f"  {mode:20s} trial{i} ok={usable} fr={c.finish_reason} "
                  f"lat={row['latency_s']}s why={row.get('schema_why')}")
        n_ok = sum(r["schema_ok"] for r in rows)
        results[mode] = {
            "trials": trials,
            "usable": n_ok,
            "success_rate": n_ok / trials,
            "direct_json_loads_rate": sum(
                1 for r in rows if r.get("parse_error") is None
            ) / trials,
            "latency": stats([r["latency_s"] for r in rows]),
            "rows": rows,
        }
    dump("phase1_structured_output", results)
    return results


# ==========================================================================
# Phase 2: raw response dump
# ==========================================================================
def phase_dump():
    print("\n=== PHASE 2: raw response dump ===")
    sysmsg = detector_prompt(SLIPPAGE_DET)
    code = load_slice()
    out = {}

    variants = {
        "plain_text": dict(response_format=None, suffix=JSON_TEXT_SUFFIX, max_tokens=4096),
        "json_schema_strict": dict(response_format=RESPONSE_FORMAT_JSON_SCHEMA,
                                   suffix="\n\nReturn findings under key \"findings\".",
                                   max_tokens=4096),
        "tiny_max_tokens_16": dict(response_format=None, suffix=JSON_TEXT_SUFFIX,
                                   max_tokens=16),
    }
    for name, cfg in variants.items():
        msgs = [
            {"role": "system", "content": sysmsg + cfg["suffix"]},
            {"role": "user", "content": user_block(code)},
        ]
        c = chat(msgs, max_tokens=cfg["max_tokens"],
                 response_format=cfg["response_format"], keep_raw=True)
        out[name] = {
            "ok": c.ok,
            "error": c.error,
            "finish_reason": c.finish_reason,
            "content_is_none": c.content is None,
            "reasoning_field_present": c.reasoning is not None,
            "raw": c.raw,
        }
        if c.raw:
            msg = c.raw["choices"][0]["message"]
            out[name]["message_keys"] = sorted(msg.keys())
            out[name]["message_nonnull_keys"] = sorted(
                k for k, v in msg.items() if v is not None
            )
            out[name]["top_level_keys"] = sorted(c.raw.keys())
            out[name]["usage"] = c.raw.get("usage")
        print(f"  {name}: finish_reason={c.finish_reason} content_none={c.content is None} "
              f"msg_keys={out[name].get('message_keys')}")
    dump("phase2_raw_dump", out)
    return out


# ==========================================================================
# Phase 3: real throughput
# ==========================================================================
def phase_throughput(trials=5):
    print("\n=== PHASE 3: real throughput (slippage detector + real slice) ===")
    sysmsg = detector_prompt(SLIPPAGE_DET) + JSON_TEXT_SUFFIX
    code = load_slice()
    rows = []
    for i in range(trials):
        # unique marker per trial so vLLM prefix-cache cannot serve a hot decode
        msgs = [
            {"role": "system", "content": sysmsg},
            {"role": "user", "content": user_block(code) + f"\n// probe-run {i}"},
        ]
        c = chat(msgs, max_tokens=4096)
        obj, perr = extract_json(c.content)
        ok, why = (schema_valid(obj) if obj is not None else (False, perr))
        rows.append({
            "trial": i,
            "latency_s": round(c.latency, 2),
            "prompt_tokens": c.prompt_tokens,
            "completion_tokens": c.completion_tokens,
            "finish_reason": c.finish_reason,
            "schema_ok": ok,
            "detected_vuln": bool(normalize(obj)) if ok else None,
            "tok_per_s": round((c.completion_tokens or 0) / c.latency, 2) if c.latency else None,
            "content_head": (c.content or "")[:200],
        })
        print(f"  trial{i}: {rows[-1]['latency_s']}s in={c.prompt_tokens} "
              f"out={c.completion_tokens} fr={c.finish_reason} "
              f"vuln={rows[-1]['detected_vuln']}")
    summary = {
        "system_prompt_chars": len(sysmsg),
        "code_chars": len(code),
        "latency_s": stats([r["latency_s"] for r in rows]),
        "prompt_tokens": stats([r["prompt_tokens"] for r in rows]),
        "completion_tokens": stats([r["completion_tokens"] for r in rows]),
        "tok_per_s": stats([r["tok_per_s"] for r in rows]),
        "rows": rows,
    }
    dump("phase3_throughput", summary)
    return summary


# ==========================================================================
# Phase 4: concurrency
# ==========================================================================
def phase_concurrency(levels=(4, 8, 16), cooldown=20):
    print("\n=== PHASE 4: concurrency ===")
    sysmsg = detector_prompt(SLIPPAGE_DET) + JSON_TEXT_SUFFIX
    code = load_slice()
    results = {}
    for n in levels:
        print(f"  -- level {n} --")
        barrier = threading.Barrier(n)

        def work(k):
            msgs = [
                {"role": "system", "content": sysmsg},
                # tiny per-request variation to defeat any response cache
                {"role": "user", "content": user_block(code) + f"\n<!-- req {k} -->"},
            ]
            barrier.wait()
            return chat(msgs, max_tokens=2048, temperature=0.2)

        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=n) as ex:
            calls = list(ex.map(work, range(n)))
        wall = time.perf_counter() - t0
        errs = [c.error for c in calls if not c.ok]
        rate_limited = sum(1 for e in errs if e and ("429" in e or "RateLimit" in e))
        results[str(n)] = {
            "concurrency": n,
            "wall_s": round(wall, 2),
            "ok": sum(c.ok for c in calls),
            "failed": len(errs),
            "rate_limited_429": rate_limited,
            "errors": errs[:5],
            "latency_s": stats([round(c.latency, 2) for c in calls if c.ok]),
            "effective_rps": round(sum(c.ok for c in calls) / wall, 3),
            "completion_tokens": stats([c.completion_tokens for c in calls if c.ok]),
            "finish_reasons": sorted({c.finish_reason for c in calls if c.ok}),
        }
        r = results[str(n)]
        print(f"   n={n} wall={r['wall_s']}s ok={r['ok']} fail={r['failed']} "
              f"429={r['rate_limited_429']} lat={r['latency_s']} rps={r['effective_rps']}")
        if errs:
            print(f"   sample errors: {errs[:2]}")
        time.sleep(cooldown)
    dump("phase4_concurrency", results)
    return results


# ==========================================================================
# Phase 5: refusal risk
# ==========================================================================
REFUSAL_PAT = re.compile(
    r"\b(i (?:can'?t|cannot|won'?t|am unable)|i'?m sorry|i apologize|as an ai|"
    r"against my|not able to (?:assist|help)|i must decline|unethical|"
    r"cannot assist with that|i do not provide)\b",
    re.I,
)
LECTURE_PAT = re.compile(
    r"(responsible disclosure|only for educational|ethical hacking|"
    r"please ensure you have permission|do not use this)", re.I
)

REFUSAL_DETECTORS = [
    "slippage_min_abount_PLACEHOLDER",  # replaced below
]


def phase_refusal(trials=3):
    print("\n=== PHASE 5: refusal / safety-lecture risk ===")
    dets = [
        "flashloan__cot_flashloan_manipulation_attack.md",
        "owasp2025__sc052025_reentrancy.md",
        "owasp2025__sc012025_improper_access_control.md",
    ]
    code = load_slice()
    results = {}
    for d in dets:
        sysmsg = detector_prompt(d) + JSON_TEXT_SUFFIX
        rows = []
        for i in range(trials):
            msgs = [
                {"role": "system", "content": sysmsg},
                {"role": "user", "content": user_block(code) + f"\n<!-- t{i} -->"},
            ]
            c = chat(msgs, max_tokens=4096, temperature=0.2)
            txt = c.content or ""
            obj, perr = extract_json(txt)
            ok, _ = (schema_valid(obj) if obj is not None else (False, perr))
            refused = bool(REFUSAL_PAT.search(txt[:1500])) and not ok
            rows.append({
                "trial": i,
                "api_ok": c.ok,
                "error": c.error,
                "finish_reason": c.finish_reason,
                "latency_s": round(c.latency, 2),
                "prompt_tokens": c.prompt_tokens,
                "completion_tokens": c.completion_tokens,
                "refused": refused,
                "safety_lecture": bool(LECTURE_PAT.search(txt)),
                "parsed_ok": ok,
                "head": txt[:250],
            })
            print(f"  {d[:38]:38s} t{i} refused={refused} parsed={ok} "
                  f"fr={c.finish_reason} err={c.error}")
        results[d] = {
            "trials": trials,
            "refusals": sum(r["refused"] for r in rows),
            "safety_lectures": sum(r["safety_lecture"] for r in rows),
            "parsed_ok": sum(r["parsed_ok"] for r in rows),
            "api_errors": sum(not r["api_ok"] for r in rows),
            "rows": rows,
        }
    dump("phase5_refusal", results)
    return results


# ==========================================================================
# Phase 6: max_tokens / truncation behaviour
# ==========================================================================
def phase_truncate():
    print("\n=== PHASE 6: truncation behaviour & max_tokens sizing ===")
    sysmsg = detector_prompt(SLIPPAGE_DET) + JSON_TEXT_SUFFIX
    code = load_slice()
    msgs = [
        {"role": "system", "content": sysmsg},
        {"role": "user", "content": user_block(code)},
    ]
    rows = []
    for mt in (16, 64, 256, 1024, 4096):
        c = chat(msgs, max_tokens=mt, temperature=0.0)
        obj, perr = extract_json(c.content)
        ok, why = (schema_valid(obj) if obj is not None else (False, perr))
        rows.append({
            "max_tokens": mt,
            "api_ok": c.ok,
            "error": c.error,
            "finish_reason": c.finish_reason,
            "completion_tokens": c.completion_tokens,
            "content_is_none": c.content is None,
            "content_len": len(c.content or ""),
            "parse_error": perr,
            "schema_ok": ok,
            "tail": (c.content or "")[-160:],
        })
        print(f"  max_tokens={mt:5d} fr={c.finish_reason} out={c.completion_tokens} "
              f"schema_ok={ok} content_none={c.content is None}")

    # how big can the *input* get?  probe an oversized context to see the error.
    big = ("// filler line to inflate the context\n" * 40000)
    c = chat([{"role": "user", "content": "count tokens:\n" + big}], max_tokens=16)
    ctx_probe = {"api_ok": c.ok, "error": c.error,
                 "prompt_tokens": c.prompt_tokens, "finish_reason": c.finish_reason}
    print(f"  oversized-context probe: ok={c.ok} pt={c.prompt_tokens} err={c.error}")

    out = {"rows": rows, "oversized_context_probe": ctx_probe}
    dump("phase6_truncation", out)
    return out


# ==========================================================================
# Phase 7: sustained load — the number that actually matters for 42k calls
# ==========================================================================
def phase_sustained(workers=16, total=96):
    print(f"\n=== PHASE 7: sustained load, {workers} workers x {total} reqs ===")
    sysmsg = detector_prompt(SLIPPAGE_DET)
    code = load_slice()
    lock = threading.Lock()
    log: list[dict] = []

    def work(k):
        msgs = [
            {"role": "system", "content": sysmsg +
             "\n\nReturn the findings under the key \"findings\"."},
            {"role": "user", "content": user_block(code) + f"\n// job {k}"},
        ]
        c = chat(msgs, max_tokens=2048, temperature=0.3,
                 response_format=RESPONSE_FORMAT_JSON_SCHEMA)
        ok = False
        if c.ok:
            obj, _ = extract_json(c.content)
            ok = obj is not None and schema_valid(obj)[0]
        with lock:
            log.append({
                "k": k, "api_ok": c.ok, "schema_ok": ok,
                "latency_s": round(c.latency, 2),
                "finish_reason": c.finish_reason,
                "completion_tokens": c.completion_tokens,
                "prompt_tokens": c.prompt_tokens,
                "error": c.error,
            })
        return c

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(work, range(total)))
    wall = time.perf_counter() - t0
    errs = [r["error"] for r in log if r["error"]]
    kinds: dict[str, int] = {}
    for e in errs:
        k = e.split(":")[0]
        if "429" in e:
            k = "HTTP429"
        elif "500" in e:
            k = "HTTP500"
        kinds[k] = kinds.get(k, 0) + 1
    out = {
        "workers": workers,
        "total": total,
        "wall_s": round(wall, 2),
        "api_ok": sum(r["api_ok"] for r in log),
        "schema_ok": sum(r["schema_ok"] for r in log),
        "errors": len(errs),
        "error_rate": round(len(errs) / total, 4),
        "error_kinds": kinds,
        "sample_errors": errs[:3],
        "throughput_rps": round(total / wall, 3),
        "latency_s": stats([r["latency_s"] for r in log if r["api_ok"]]),
        "prompt_tokens": stats([r["prompt_tokens"] for r in log if r["api_ok"]]),
        "completion_tokens": stats([r["completion_tokens"] for r in log if r["api_ok"]]),
        "rows": sorted(log, key=lambda r: r["k"]),
    }
    print(f"  wall={out['wall_s']}s rps={out['throughput_rps']} ok={out['api_ok']}/{total} "
          f"schema_ok={out['schema_ok']} errors={out['error_kinds']}")
    print(f"  latency={out['latency_s']}")
    dump(f"phase7_sustained_w{workers}", out)
    return out


PHASES = {
    "schema": phase_schema,
    "sustained": phase_sustained,
    "dump": phase_dump,
    "throughput": phase_throughput,
    "concurrency": phase_concurrency,
    "refusal": phase_refusal,
    "truncate": phase_truncate,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", nargs="+", choices=list(PHASES) + ["all"])
    ap.add_argument("--levels", type=str, default="4,8,16",
                    help="concurrency levels, e.g. 4,8,16,32")
    a = ap.parse_args()
    names = list(PHASES) if "all" in a.phase else a.phase
    for n in names:
        if n == "concurrency":
            phase_concurrency(tuple(int(x) for x in a.levels.split(",")))
        else:
            PHASES[n]()


if __name__ == "__main__":
    main()

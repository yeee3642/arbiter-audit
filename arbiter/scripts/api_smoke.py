#!/usr/bin/env python3
"""Send one minimal request through the configured AIS3 gateway."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from arbiter.gateway import DEFAULT_BASE_URL, Gateway, GatewayError  # noqa: E402


def main() -> int:
    model = os.environ.get("AIS3_MODEL", "ais3/nemotron-3-ultra-550b")
    base_url = os.environ.get("AIS3_BASE_URL", DEFAULT_BASE_URL)

    try:
        gateway = Gateway(
            model=model,
            base_url=base_url,
            rpm=1,
            timeout=120,
            max_retries=1,
        )
        message = gateway.chat(
            [
                {
                    "role": "user",
                    "content": "Reply with exactly AIS3_OK and nothing else.",
                }
            ],
            max_tokens=32,
            temperature=0,
            tag="connection-smoke-test",
        )
    except GatewayError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    reply = str(message.get("content") or "").strip()
    if reply != "AIS3_OK":
        print(f"FAIL: unexpected reply {reply[:100]!r}", file=sys.stderr)
        return 1

    usage = gateway.usage.as_dict()
    print("PASS: AIS3 gateway replied AIS3_OK")
    print(f"model: {', '.join(usage['models_seen']) or model}")
    print(
        "usage: "
        + json.dumps(
            {
                "requests": usage["requests"],
                "prompt_tokens": usage["prompt_tokens"],
                "completion_tokens": usage["completion_tokens"],
                "cost_usd": usage["cost_usd"],
                "retries": usage["retries"],
                "http_errors": usage["http_errors"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

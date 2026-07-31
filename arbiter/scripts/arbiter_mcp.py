#!/usr/bin/env python3
"""ARBITER's tool surface, served over MCP so another agent can drive the audit.

The point of this file is what it does NOT contain. There is no predicate here, no
composition, no gate -- every one of those stays in `arbiter/workspace.py`, reached
through the same `ToolDispatcher` the project's own loop uses. What changes is only who
decides which tool to call next.

That is the claim worth testing. If the harness is the contribution, then swapping the
agent for a different one should leave the verdict machinery untouched and still produce
adjudicated findings. If swapping the agent quietly changes what counts as a finding,
the contribution was never the harness.

Hand-rolled JSON-RPC over stdio rather than the `mcp` package, for the same reason the
rest of this repo vendors nothing: a dependency that fails to resolve is indistinguishable
from a tool that found nothing.

    arbiter_mcp.py --source examples/StakingVault.sol --sample-id demo \
                   --root /tmp/omp-ws --outcome /tmp/omp-outcome.json
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.tools import ToolDispatcher, tool_schemas  # noqa: E402
from arbiter.workspace import Workspace  # noqa: E402

PROTOCOL = "2024-11-05"


def _mcp_tools(predicates) -> list[dict]:
    """ARBITER's schemas, in MCP's shape.

    `tool_schemas` speaks the OpenAI function-calling dialect. The only difference that
    matters is the key holding the JSON Schema, so both spellings are accepted rather
    than assumed -- a wrong guess here would present the agent with tools that have no
    parameters, which it would happily call.
    """
    out = []
    for s in tool_schemas(predicates) if predicates else tool_schemas():
        fn = s.get("function", s)
        out.append({
            "name": fn["name"],
            "description": fn.get("description", ""),
            "inputSchema": fn.get("parameters") or fn.get("input_schema")
            or {"type": "object", "properties": {}},
        })
    return out


class Server:
    def __init__(self, ws: Workspace, outcome_path: Path, predicates) -> None:
        self.disp = ToolDispatcher(ws)
        self.outcome_path = outcome_path
        self.tools = _mcp_tools(predicates)
        self.terminal = False
        self.calls: list[dict] = []

    def _flush(self) -> None:
        """Write the verdict out after every terminal tool, not only at exit.

        The host may kill us the moment the agent stops talking, and a verdict that only
        exists in memory is a verdict nobody scored.
        """
        rec = self.disp.outcome.as_dict()
        rec["tool_calls"] = self.calls
        rec["terminal"] = self.terminal
        self.outcome_path.write_text(
            json.dumps(rec, indent=1, ensure_ascii=False), encoding="utf-8")

    def handle(self, req: dict) -> dict | None:
        method = req.get("method")
        rid = req.get("id")

        if method == "initialize":
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": PROTOCOL,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "arbiter", "version": "1"},
            }}

        if method in ("notifications/initialized", "notifications/cancelled"):
            return None

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid,
                    "result": {"tools": self.tools}}

        if method == "tools/call":
            params = req.get("params") or {}
            name = params.get("name", "")
            args = params.get("arguments") or {}
            try:
                text, terminal = self.disp.dispatch(name, args)
            except Exception as exc:  # noqa: BLE001
                # Surfaced to the agent rather than swallowed: a tool that fails
                # silently teaches the agent that its call worked.
                text, terminal = (
                    f"{type(exc).__name__}: {exc}\n"
                    f"{traceback.format_exc(limit=3)}", False)
                self.calls.append({"tool": name, "error": str(exc)[:200]})
            else:
                self.calls.append({"tool": name, "terminal": terminal,
                                   "chars": len(text)})
            if terminal:
                self.terminal = True
            self._flush()
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": text}],
                "isError": False,
            }}

        if rid is None:
            return None
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": f"unknown method {method}"}}

    def serve(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue
            reply = self.handle(req)
            if reply is not None:
                sys.stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
                sys.stdout.flush()
        self._flush()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", type=Path, required=True)
    ap.add_argument("--sample-id", default="omp")
    ap.add_argument("--root", type=Path, default=Path("/tmp/omp-ws"))
    ap.add_argument("--outcome", type=Path, required=True)
    ap.add_argument("--predicates", default="",
                    help="comma separated; empty means the harness default")
    args = ap.parse_args()

    # Refused here as well as in the dispatcher, and the belt is not redundant with the
    # braces. The dispatcher's rule makes a missing compiler produce `no_verdict` instead
    # of `safe`; this one stops the host burning gateway requests to arrive there.
    if not shutil.which("forge"):
        sys.stderr.write(
            "forge is not on PATH. Every finding this server can produce is an "
            "execution transcript, so without a compiler it can only refuse.\n")
        return 2

    ws = Workspace(args.root, args.sample_id,
                   args.source.read_text(encoding="utf-8"))
    preds = tuple(p for p in args.predicates.split(",") if p.strip())
    Server(ws, args.outcome, preds or None).serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

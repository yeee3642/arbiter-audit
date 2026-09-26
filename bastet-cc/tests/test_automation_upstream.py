from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from bastet_cc.automation.contracts import BudgetLimits
from bastet_cc.automation.server import RunningServer, build_service

FLASHLOAN_SOLIDITY_FIXTURE = """pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);
}

contract FlashloanVault {
    IERC20 public immutable asset;

    constructor(IERC20 token) {
        asset = token;
    }

    function flashLoan(uint256 amount, address receiver) external {
        require(amount > 0, "amount");
        require(receiver != address(0), "receiver");
        asset.transfer(receiver, amount);
    }
}
"""


def _write_flashloan_workflow(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    workflow = {
        "id": "wf-flashloan",
        "name": "flashloan",
        "nodes": [
            {
                "id": "webhook-node",
                "name": "Webhook",
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 2,
                "parameters": {
                    "httpMethod": "POST",
                    "path": "flashloan_minAmount",
                    "responseMode": "responseNode",
                    "options": {},
                },
            },
            {
                "id": "chain-node",
                "name": "Flashloan Detector",
                "type": "@n8n/n8n-nodes-langchain.chainLlm",
                "typeVersion": 1,
                "parameters": {
                    "model": "gpt-4o-mini",
                    "messages": {
                        "messageValues": [
                            {
                                "message": (
                                    "You are the flashloan detector. Return only a JSON array "
                                    "of audit reports."
                                )
                            }
                        ]
                    },
                },
            },
            {
                "id": "parser-node",
                "name": "Structured Output",
                "type": "@n8n/n8n-nodes-langchain.outputParserStructured",
                "typeVersion": 1,
                "parameters": {
                    "inputSchema": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "summary": {"type": "string"},
                                "severity": {"type": "string"},
                                "vulnerability_details": {"type": "object"},
                                "code_snippet": {"type": "array"},
                                "recommendation": {"type": "string"},
                            },
                            "required": [
                                "summary",
                                "vulnerability_details",
                                "recommendation",
                            ],
                        },
                    }
                },
            },
        ],
    }
    (root / "flashloan.json").write_text(json.dumps(workflow, indent=2), encoding="utf-8")
    return root


def _require_upstream_env() -> tuple[Path, str]:
    root = os.environ.get("BASTET_UPSTREAM_ROOT")
    python = os.environ.get("BASTET_UPSTREAM_PYTHON")
    if not root or not python:
        pytest.skip("set BASTET_UPSTREAM_ROOT and BASTET_UPSTREAM_PYTHON to enable upstream automation coverage")
    root_path = Path(root)
    if not root_path.exists():
        pytest.skip(f"BASTET_UPSTREAM_ROOT does not exist: {root_path}")
    if not Path(python).exists():
        pytest.skip(f"BASTET_UPSTREAM_PYTHON does not exist: {python}")
    return root_path, python


def _tree_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        hashes[relative] = digest
    return hashes


def test_upstream_cli_runs_against_the_shim_without_modifying_the_checkout(tmp_path: Path):
    upstream_root, python_path = _require_upstream_env()
    before = _tree_hashes(upstream_root)

    workflow_root = _write_flashloan_workflow(tmp_path / "workflow-root")
    output_dir = tmp_path / "upstream-output"
    service = build_service(
        workflow_root=workflow_root,
        experiment_id="exp-upstream",
        subject_id="subject-upstream",
        budget_limits=BudgetLimits(global_calls=20, global_tokens=200_000, per_arm_calls=10, per_arm_tokens=100_000),
        ledger_path=tmp_path / "artefacts" / "ledger.jsonl",
        manifest_path=tmp_path / "artefacts" / "manifest.json",
        selected_workflow="flashloan",
    )
    env = os.environ.copy()
    env.pop("AIS3_API_KEY", None)
    env.pop("OPENAI_API_KEY", None)
    env["PYTHONPATH"] = env.get("PYTHONPATH", "")
    # Upstream prints emoji through tqdm. Windows otherwise chooses cp950 for
    # the captured pipe and crashes after a valid finding is parsed.
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    with RunningServer(service) as server:
        result = subprocess.run(
            [
                python_path,
                "cli/main.py",
                "scan",
                "--folder-path",
                str(upstream_root / "dataset" / "scan_queue"),
                "--n8n-url",
                server.url,
                "--report-name",
                "automation_upstream",
                "--output-path",
                str(output_dir) + os.sep,
                "--output-format",
                "json",
            ],
            cwd=upstream_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=300,
        )

    assert result.returncode == 0, (
        f"stdout:\n{result.stdout}\n\nstderr:\n{result.stderr}"
    )
    report_path = output_dir / "automation_upstream.json"
    assert report_path.exists(), f"missing report: {report_path}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report, "upstream CLI produced an empty JSON report"
    after = _tree_hashes(upstream_root)
    assert after == before

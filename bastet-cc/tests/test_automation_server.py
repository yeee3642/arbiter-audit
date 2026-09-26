from __future__ import annotations

import json
from http.client import HTTPConnection
from pathlib import Path
from urllib.parse import urlparse

import httpx
import pytest

from bastet_cc.automation.contracts import AIS3_PINNED_MODEL, BudgetLimits, ConfigurationMismatch
from bastet_cc.automation.server import MAX_REQUEST_BYTES, RunningServer, build_service, create_server
from bastet_cc.cli import DEFAULT_MODEL

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


@pytest.fixture
def automation_paths(tmp_path: Path) -> dict[str, Path]:
    workflow_root = _write_flashloan_workflow(tmp_path / "workflow-root")
    artefacts = tmp_path / "artefacts"
    return {
        "workflow_root": workflow_root,
        "ledger_path": artefacts / "ledger.jsonl",
        "manifest_path": artefacts / "manifest.json",
    }


@pytest.fixture
def service(automation_paths: dict[str, Path]):
    return build_service(
        workflow_root=automation_paths["workflow_root"],
        experiment_id="exp-flashloan",
        subject_id="subject-flashloan",
        budget_limits=BudgetLimits(
            global_calls=6,
            global_tokens=50_000,
            per_arm_calls=3,
            per_arm_tokens=25_000,
        ),
        ledger_path=automation_paths["ledger_path"],
        manifest_path=automation_paths["manifest_path"],
        selected_workflow="flashloan",
    )


@pytest.fixture
def live_server(service):
    with RunningServer(service) as server:
        yield server


@pytest.fixture
def client():
    with httpx.Client(timeout=10.0) as session:
        yield session


def _openai_payload(body: str = FLASHLOAN_SOLIDITY_FIXTURE, model: str = AIS3_PINNED_MODEL) -> dict:
    return {
        "model": model,
        "temperature": 0,
        "max_tokens": 256,
        "messages": [
            {
                "role": "system",
                "content": 'Review the contract and return only {"findings": []} or findings.',
            },
            {"role": "user", "content": body},
        ],
    }


def test_health_exposes_the_server_profile(live_server: RunningServer, client: httpx.Client):
    response = client.get(f"{live_server.url}/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "experiment_id": "exp-flashloan",
        "subject_id": "subject-flashloan",
        "provider_mode": "mock",
        "model": AIS3_PINNED_MODEL,
        "workflow": "flashloan",
        "claim_level": "pipeline-readiness-only",
    }


def test_manifest_persists_the_budget_fingerprint(service, live_server: RunningServer, client: httpx.Client):
    response = client.get(f"{live_server.url}/manifest")

    assert response.status_code == 200
    manifest = response.json()
    assert manifest["fingerprint"] == service.profile.fingerprint
    assert manifest["budget"] == service.profile.budget.to_dict()


def test_models_surface_exposes_only_the_exact_pinned_model(live_server: RunningServer, client: httpx.Client):
    response = client.get(f"{live_server.url}/v1/models")

    assert response.status_code == 200
    assert response.json()["data"] == [
        {
            "id": AIS3_PINNED_MODEL,
            "object": "model",
            "created": 0,
            "owned_by": "ais3",
        }
    ]


def test_cli_default_uses_the_same_pinned_model_as_both_automation_arms():
    assert DEFAULT_MODEL == AIS3_PINNED_MODEL


def test_openai_completion_returns_a_schema_compatible_completion(
    live_server: RunningServer,
    client: httpx.Client,
):
    response = client.post(f"{live_server.url}/v1/chat/completions", json=_openai_payload())

    assert response.status_code == 200
    payload = response.json()
    assert payload["model"] == AIS3_PINNED_MODEL
    assert payload["choices"][0]["message"]["role"] == "assistant"
    assert payload["choices"][0]["finish_reason"] == "stop"
    assert "findings" in payload["choices"][0]["message"]["content"]
    assert payload["usage"]["total_tokens"] > 0


def test_n8n_surface_lists_the_selected_workflow(live_server: RunningServer, client: httpx.Client):
    response = client.get(f"{live_server.url}/api/v1/workflows")

    assert response.status_code == 200
    workflows = response.json()["data"]
    assert len(workflows) == 1
    assert workflows[0]["name"] == "flashloan"
    assert workflows[0]["active"] is True
    assert workflows[0]["nodes"][0]["parameters"]["path"] == "flashloan_minAmount"


def test_n8n_webhook_submission_creates_a_finished_execution_record(
    live_server: RunningServer,
    client: httpx.Client,
):
    submit = client.post(
        f"{live_server.url}/webhook/flashloan_minAmount",
        json={"prompt": FLASHLOAN_SOLIDITY_FIXTURE},
    )
    execution_id = submit.text

    response = client.get(f"{live_server.url}/api/v1/executions/{execution_id}")

    assert submit.status_code == 200
    assert response.status_code == 200
    payload = response.json()
    output = payload["data"]["resultData"]["runData"]["flashloan"][0]["data"]["main"][0][0]["json"]["output"]
    assert payload["finished"] is True
    assert output[0]["summary"].startswith("Deterministic mock audit")
    assert output[0]["vulnerability_details"]["function_name"]


def test_budget_and_ledger_account_for_both_surfaces_in_one_server(
    automation_paths: dict[str, Path],
    live_server: RunningServer,
    client: httpx.Client,
):
    openai = client.post(f"{live_server.url}/v1/chat/completions", json=_openai_payload())
    webhook = client.post(
        f"{live_server.url}/webhook/flashloan_minAmount",
        json={"prompt": FLASHLOAN_SOLIDITY_FIXTURE},
    )
    budget = client.get(f"{live_server.url}/budget")

    assert openai.status_code == 200
    assert webhook.status_code == 200
    assert budget.status_code == 200
    snapshot = budget.json()
    assert snapshot["budget"]["global"]["calls"] == 2
    assert snapshot["budget"]["arms"]["bastet-cc"]["calls"] == 1
    assert snapshot["budget"]["arms"]["upstream"]["calls"] == 1
    assert snapshot["ledger"]["by_arm"] == {"bastet-cc": 1, "upstream": 1}
    assert snapshot["ledger"]["records"] == 4
    assert snapshot["ledger"]["pending_reservations"] == 0
    ledger_records = [
        json.loads(line)
        for line in automation_paths["ledger_path"].read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert {record["surface"] for record in ledger_records} == {"openai", "n8n"}


def test_openai_surface_rejects_an_exact_model_mismatch(live_server: RunningServer, client: httpx.Client):
    response = client.post(
        f"{live_server.url}/v1/chat/completions",
        json=_openai_payload(model="ais3/not-the-pinned-model"),
    )

    assert response.status_code == 400
    assert response.json()["error"]["type"] == "ModelMismatch"


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/v1/chat/completions", _openai_payload()),
        ("/webhook/flashloan_minAmount", {"prompt": FLASHLOAN_SOLIDITY_FIXTURE}),
    ],
)
def test_experiment_or_subject_mismatch_returns_409_on_both_surfaces(
    live_server: RunningServer,
    client: httpx.Client,
    path: str,
    payload: dict,
):
    response = client.post(
        f"{live_server.url}{path}",
        headers={"X-Bastet-Subject": "wrong-subject"},
        json=payload,
    )

    assert response.status_code == 409
    assert response.json()["error"]["type"] == "ConfigurationMismatch"


def test_malformed_request_body_returns_400(live_server: RunningServer, client: httpx.Client):
    response = client.post(
        f"{live_server.url}/v1/chat/completions",
        content=b"{not-json",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json()["error"]["message"] == "request body is not valid JSON"


def test_request_body_larger_than_the_cap_is_rejected(live_server: RunningServer):
    target = urlparse(live_server.url)
    connection = HTTPConnection(target.hostname, target.port, timeout=10)
    try:
        connection.putrequest("POST", "/webhook/flashloan_minAmount")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(MAX_REQUEST_BYTES + 1))
        connection.endheaders()
        response = connection.getresponse()
        payload = json.loads(response.read())
    finally:
        connection.close()

    assert response.status == 400
    assert "request body must be 1.." in payload["error"]["message"]


@pytest.mark.parametrize("host", ["0.0.0.0", "::1", "127.0.0.2"])
def test_server_refuses_to_bind_anything_but_supported_ipv4_loopback(service, host: str):
    with pytest.raises(ValueError, match="loopback"):
        create_server(service, host=host, port=0)
    service.close()


def test_live_mode_fails_closed_without_a_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.delenv("AIS3_API_KEY", raising=False)

    with pytest.raises(ValueError, match="live mode requires AIS3_API_KEY"):
        build_service(
            workflow_root=_write_flashloan_workflow(tmp_path / "workflow-root"),
            experiment_id="exp-live",
            subject_id="subject-live",
            budget_limits=BudgetLimits(),
            ledger_path=tmp_path / "ledger.jsonl",
            manifest_path=tmp_path / "manifest.json",
            selected_workflow="flashloan",
            live=True,
        )


def test_restart_rejects_a_manifest_budget_mismatch(tmp_path: Path):
    workflow_root = _write_flashloan_workflow(tmp_path / "workflow-root")
    manifest_path = tmp_path / "run" / "manifest.json"
    ledger_path = tmp_path / "run" / "ledger.jsonl"
    first = build_service(
        workflow_root=workflow_root,
        experiment_id="exp-restart",
        subject_id="subject-restart",
        budget_limits=BudgetLimits(global_calls=4, global_tokens=20_000, per_arm_calls=2, per_arm_tokens=10_000),
        ledger_path=ledger_path,
        manifest_path=manifest_path,
        selected_workflow="flashloan",
    )
    first.close()

    with pytest.raises(ConfigurationMismatch, match="fingerprint differs"):
        build_service(
            workflow_root=workflow_root,
            experiment_id="exp-restart",
            subject_id="subject-restart",
            budget_limits=BudgetLimits(global_calls=5, global_tokens=20_000, per_arm_calls=2, per_arm_tokens=10_000),
            ledger_path=ledger_path,
            manifest_path=manifest_path,
            selected_workflow="flashloan",
        )


def test_restart_rehydrates_spent_budget_and_denies_the_next_call(tmp_path: Path):
    workflow_root = _write_flashloan_workflow(tmp_path / "workflow-root")
    manifest_path = tmp_path / "run" / "manifest.json"
    ledger_path = tmp_path / "run" / "ledger.jsonl"
    limits = BudgetLimits(
        global_calls=1,
        global_tokens=20_000,
        per_arm_calls=1,
        per_arm_tokens=20_000,
    )
    first = build_service(
        workflow_root=workflow_root,
        experiment_id="exp-rehydrate",
        subject_id="subject-rehydrate",
        budget_limits=limits,
        ledger_path=ledger_path,
        manifest_path=manifest_path,
        selected_workflow="flashloan",
    )
    with RunningServer(first) as server, httpx.Client(timeout=10.0) as session:
        response = session.post(
            f"{server.url}/v1/chat/completions",
            json=_openai_payload(),
        )
        assert response.status_code == 200

    second = build_service(
        workflow_root=workflow_root,
        experiment_id="exp-rehydrate",
        subject_id="subject-rehydrate",
        budget_limits=limits,
        ledger_path=ledger_path,
        manifest_path=manifest_path,
        selected_workflow="flashloan",
    )
    assert second.budget.snapshot()["global"]["calls"] == 1
    with RunningServer(second) as server, httpx.Client(timeout=10.0) as session:
        response = session.post(
            f"{server.url}/v1/chat/completions",
            json=_openai_payload(),
        )
        assert response.status_code == 429
        assert response.json()["error"]["type"] == "BudgetExceeded"


def test_restart_reloads_a_completed_upstream_execution(tmp_path: Path):
    workflow_root = _write_flashloan_workflow(tmp_path / "workflow-root")
    manifest_path = tmp_path / "run" / "manifest.json"
    ledger_path = tmp_path / "run" / "ledger.jsonl"
    limits = BudgetLimits(
        global_calls=4,
        global_tokens=40_000,
        per_arm_calls=2,
        per_arm_tokens=20_000,
    )
    first = build_service(
        workflow_root=workflow_root,
        experiment_id="exp-execution-restart",
        subject_id="subject-execution-restart",
        budget_limits=limits,
        ledger_path=ledger_path,
        manifest_path=manifest_path,
        selected_workflow="flashloan",
    )
    with RunningServer(first) as server, httpx.Client(timeout=10.0) as session:
        submitted = session.post(
            f"{server.url}/webhook/flashloan_minAmount",
            json={"prompt": FLASHLOAN_SOLIDITY_FIXTURE},
        )
        assert submitted.status_code == 200
        execution_id = submitted.text
        before = session.get(
            f"{server.url}/api/v1/executions/{execution_id}?includeData=true"
        )
        assert before.status_code == 200

    second = build_service(
        workflow_root=workflow_root,
        experiment_id="exp-execution-restart",
        subject_id="subject-execution-restart",
        budget_limits=limits,
        ledger_path=ledger_path,
        manifest_path=manifest_path,
        selected_workflow="flashloan",
    )
    assert second.executions.count() == 1
    with RunningServer(second) as server, httpx.Client(timeout=10.0) as session:
        after = session.get(
            f"{server.url}/api/v1/executions/{execution_id}?includeData=true"
        )
        assert after.status_code == 200
        assert after.json() == before.json()


def test_restart_fails_closed_on_a_corrupt_execution_store(tmp_path: Path):
    workflow_root = _write_flashloan_workflow(tmp_path / "workflow-root")
    manifest_path = tmp_path / "run" / "manifest.json"
    ledger_path = tmp_path / "run" / "ledger.jsonl"
    first = build_service(
        workflow_root=workflow_root,
        experiment_id="exp-corrupt-executions",
        subject_id="subject-corrupt-executions",
        budget_limits=BudgetLimits(),
        ledger_path=ledger_path,
        manifest_path=manifest_path,
        selected_workflow="flashloan",
    )
    first.close()
    (manifest_path.parent / "executions.jsonl").write_text(
        "{not-json\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationMismatch, match="execution store line 1"):
        build_service(
            workflow_root=workflow_root,
            experiment_id="exp-corrupt-executions",
            subject_id="subject-corrupt-executions",
            budget_limits=BudgetLimits(),
            ledger_path=ledger_path,
            manifest_path=manifest_path,
            selected_workflow="flashloan",
        )


def test_caller_request_id_and_invalid_stage_are_not_persisted(
    automation_paths: dict[str, Path],
    live_server: RunningServer,
    client: httpx.Client,
):
    caller_value = "d" * 64
    success = client.post(
        f"{live_server.url}/v1/chat/completions",
        headers={"X-Bastet-Request": caller_value},
        json=_openai_payload(),
    )
    rejected = client.post(
        f"{live_server.url}/v1/chat/completions",
        headers={
            "X-Bastet-Request": caller_value,
            "X-Bastet-Stage": "caller-controlled-stage",
        },
        json=_openai_payload(),
    )

    assert success.status_code == 200
    assert rejected.status_code == 400
    ledger_blob = automation_paths["ledger_path"].read_text(encoding="utf-8")
    records = [
        json.loads(line)
        for line in ledger_blob.splitlines()
        if line.strip()
    ]
    assert len(records) == 2
    assert {record["event"] for record in records} == {
        "attempt_reserved",
        "attempt_settled",
    }
    assert all(record["request_id"] != caller_value for record in records)
    assert all(len(record["request_id"]) == 32 for record in records)
    assert caller_value not in ledger_blob


def test_artifacts_and_error_paths_do_not_leak_request_bodies_or_secrets(
    automation_paths: dict[str, Path],
    live_server: RunningServer,
    client: httpx.Client,
):
    secret_body = "super-secret-body-marker"
    secret_header = ("Bear" + "er ") + "super-secret-header-marker"
    success = client.post(
        f"{live_server.url}/v1/chat/completions",
        headers={"Authorization": secret_header},
        json=_openai_payload(body=FLASHLOAN_SOLIDITY_FIXTURE + "\n// " + secret_body),
    )
    failure = client.post(
        f"{live_server.url}/v1/chat/completions",
        headers={"Authorization": secret_header},
        json=_openai_payload(body=secret_body, model="bad-model"),
    )

    assert success.status_code == 200
    assert failure.status_code == 400
    manifest_blob = automation_paths["manifest_path"].read_text(encoding="utf-8")
    ledger_blob = automation_paths["ledger_path"].read_text(encoding="utf-8")
    assert secret_body not in ledger_blob
    assert secret_body not in manifest_blob
    assert "super-secret-header-marker" not in ledger_blob
    assert "super-secret-header-marker" not in manifest_blob
    assert '"messages"' not in ledger_blob
    assert secret_body not in failure.text
    assert "super-secret-header-marker" not in failure.text

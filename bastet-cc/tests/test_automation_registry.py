from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bastet_cc.automation.contracts import (
    AIS3_PINNED_MODEL,
    BudgetLimits,
    GatewayProfile,
    sha256_text,
)
from bastet_cc.automation.executions import ExecutionStore
from bastet_cc.automation.registry import (
    DuplicateSelectedWorkflow,
    EmptyWebhookRoute,
    UnsupportedSelectedWorkflow,
    WorkflowRegistry,
)
from bastet_cc.automation.surfaces.n8n import (
    N8NSurface,
    ProviderOutputMalformed,
    UnknownExecution,
    UnknownWebhookRoute,
)


_MISSING = object()


def _profile() -> GatewayProfile:
    return GatewayProfile(
        experiment_id="exp",
        subject_id="subject",
        provider_mode="mock",
        selected_workflow="flashloan",
        workflow_sha256="0" * 64,
        prompt_sha256="1" * 64,
        budget=BudgetLimits(),
    )


class _GatewayStub:
    def __init__(self, text: str, request_id: str = "provider-request") -> None:
        self.profile = _profile()
        self._text = text
        self._request_id = request_id
        self.requests = []

    def complete(self, request):
        self.requests.append(request)
        return SimpleNamespace(text=self._text, request_id=self._request_id)


def _workflow(
    *,
    name: str,
    workflow_id: str | None = None,
    route: object = "flashloan",
    chain_messages: tuple[tuple[str, ...], ...] = (("=system prompt",),),
    chain_models: tuple[object, ...] | None = None,
    parser_schema: dict[str, object] | None = None,
    schema_as_string: bool = True,
    extra_nodes: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    nodes: list[dict[str, object]] = []
    if route is not _MISSING:
        nodes.append(
            {
                "id": f"{name}-webhook",
                "name": "Webhook",
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 2,
                "position": [260, 300],
                "parameters": {
                    "path": route,
                    "httpMethod": "POST",
                    "responseMode": "responseNode",
                    "options": {"responseCode": 200},
                },
            }
        )

    models = chain_models or tuple("gpt-4o-mini" for _ in chain_messages)
    for idx, messages in enumerate(chain_messages):
        nodes.append(
            {
                "id": f"{name}-chain-{idx}",
                "name": f"Chain {idx}",
                "type": "@n8n/n8n-nodes-langchain.chainLlm",
                "parameters": {
                    "model": models[idx],
                    "messages": {
                        "messageValues": [
                            {"message": message} for message in messages
                        ]
                    },
                },
            }
        )

    if parser_schema is not None:
        nodes.append(
            {
                "id": f"{name}-parser",
                "name": "Parser",
                "type": "@n8n/n8n-nodes-langchain.outputParserStructured",
                "parameters": {
                    "inputSchema": (
                        json.dumps(parser_schema)
                        if schema_as_string
                        else parser_schema
                    )
                },
            }
        )

    if extra_nodes:
        nodes.extend(extra_nodes)

    return {
        "id": workflow_id or name,
        "name": name,
        "nodes": nodes,
    }


def _write_workflow(root: Path, filename: str, payload: dict[str, object]) -> tuple[Path, str]:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    path = root / filename
    path.write_text(raw, encoding="utf-8")
    return path, raw


def _load_registry(root: Path) -> WorkflowRegistry:
    return WorkflowRegistry.load(root, selected="flashloan")


def _valid_report() -> list[dict[str, object]]:
    return [
        {
            "summary": "flashloan issue",
            "severity": "medium",
            "vulnerability_details": {
                "function_name": "borrow",
                "description": "borrow path is exposed",
            },
            "code_snippet": ["function borrow() external {}"],
            "recommendation": "add validation",
        }
    ]


def test_registry_load_is_deterministic(tmp_path):
    _write_workflow(tmp_path, "flashloan.json", _workflow(name="flashloan"))
    _write_workflow(tmp_path, "dos.json", _workflow(name="dos", route="dos"))

    left = _load_registry(tmp_path)
    right = _load_registry(tmp_path)

    assert tuple(spec.name for spec in left.workflows) == ("dos", "flashloan")
    assert tuple(spec.name for spec in right.workflows) == ("dos", "flashloan")
    assert left.selected == right.selected
    assert left.public_workflows() == right.public_workflows()
    assert left.route_collisions == right.route_collisions


def test_registry_normalizes_leading_equals_in_routes(tmp_path):
    _write_workflow(tmp_path, "flashloan.json", _workflow(name="flashloan", route="=flashloan"))

    registry = _load_registry(tmp_path)

    assert registry.selected.webhook_path == "flashloan"
    assert registry.selected_route("=flashloan").name == "flashloan"
    assert registry.public_workflows()[0]["nodes"][0]["parameters"]["path"] == "flashloan"


def test_public_workflows_exposes_only_the_selected_active_workflow(tmp_path):
    _write_workflow(tmp_path, "flashloan.json", _workflow(name="flashloan"))
    _write_workflow(tmp_path, "dos.json", _workflow(name="dos", route="dos"))

    registry = _load_registry(tmp_path)

    assert registry.public_workflows() == [
        {
            "id": "flashloan",
            "name": "flashloan",
            "active": True,
            "nodes": [
                {
                    "parameters": {
                        "httpMethod": "POST",
                        "path": "flashloan",
                        "responseMode": "responseNode",
                        "options": {"responseCode": 200},
                    },
                    "type": "n8n-nodes-base.webhook",
                    "typeVersion": 2,
                    "id": "flashloan-webhook",
                    "name": "Webhook",
                    "position": [260, 300],
                }
            ],
        }
    ]


def test_duplicate_route_collision_is_recorded_but_selected_workflow_still_resolves(tmp_path):
    _write_workflow(tmp_path, "flashloan.json", _workflow(name="flashloan", route="flashloan"))
    _write_workflow(tmp_path, "other.json", _workflow(name="other", route="flashloan"))

    registry = _load_registry(tmp_path)

    assert registry.route_collisions == {"flashloan": ("flashloan", "other")}
    assert registry.selected_route("/flashloan").name == "flashloan"
    assert registry.get("other").public_workflow["active"] is False


def test_duplicate_selected_workflow_names_are_rejected(tmp_path):
    _write_workflow(tmp_path, "flashloan-a.json", _workflow(name="flashloan", route="flashloan-a"))
    _write_workflow(tmp_path, "flashloan-b.json", _workflow(name="flashloan", route="flashloan-b"))

    with pytest.raises(DuplicateSelectedWorkflow, match="multiple upstream JSON files"):
        _load_registry(tmp_path)


@pytest.mark.parametrize(
    "route",
    [
        _MISSING,
        "",
        "   ",
        "=",
    ],
)
def test_missing_or_empty_webhook_route_is_rejected(tmp_path, route):
    _write_workflow(tmp_path, "flashloan.json", _workflow(name="flashloan", route=route))

    with pytest.raises(EmptyWebhookRoute, match="empty webhook route"):
        _load_registry(tmp_path)


@pytest.mark.parametrize(
    "chain_messages",
    [
        (),
        (("=one",), ("=two",)),
    ],
)
def test_selected_workflow_requires_exactly_one_chain_llm_node(tmp_path, chain_messages):
    _write_workflow(
        tmp_path,
        "flashloan.json",
        _workflow(name="flashloan", chain_messages=chain_messages),
    )

    with pytest.raises(UnsupportedSelectedWorkflow, match="exactly one chainLlm node"):
        _load_registry(tmp_path)


def test_registry_extracts_prompt_model_schema_and_hashes(tmp_path):
    parser_schema = {
        "type": "array",
        "items": {"type": "object", "properties": {"summary": {"type": "string"}}},
    }
    payload = _workflow(
        name="flashloan",
        route="=/flashloan",
        chain_messages=(("= first prompt ", "", " second prompt  "),),
        chain_models=({"value": "gpt-4o-mini"},),
        parser_schema=parser_schema,
        extra_nodes=[
            {
                "id": "chat-model",
                "name": "Chat model",
                "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi",
                "parameters": {"model": {"cachedResultName": "gpt-4o"}},
            }
        ],
    )
    _, raw = _write_workflow(tmp_path, "flashloan.json", payload)

    registry = _load_registry(tmp_path)
    workflow = registry.selected

    assert workflow.prompt == "first prompt\n\nsecond prompt"
    assert workflow.declared_models == ("gpt-4o", "gpt-4o-mini")
    assert workflow.parser_schema == parser_schema
    assert workflow.workflow_sha256 == sha256_text(raw)
    assert workflow.prompt_sha256 == sha256_text(workflow.prompt)


def test_registry_load_leaves_the_frozen_input_file_digest_unchanged(tmp_path):
    path, raw = _write_workflow(
        tmp_path,
        "flashloan.json",
        _workflow(name="flashloan", route="=/flashloan"),
    )
    before = sha256_text(raw)

    registry = _load_registry(tmp_path)
    registry.public_workflows()

    after_raw = path.read_text(encoding="utf-8")
    assert after_raw == raw
    assert sha256_text(after_raw) == before
    assert registry.selected.workflow_sha256 == before


def test_n8n_submit_builds_the_upstream_request_contract(tmp_path):
    _write_workflow(
        tmp_path,
        "flashloan.json",
        _workflow(name="flashloan", chain_messages=(("=registry system prompt",),)),
    )
    registry = _load_registry(tmp_path)
    gateway = _GatewayStub(json.dumps(_valid_report()))
    surface = N8NSurface(
        registry,
        gateway,
        ExecutionStore(tmp_path / "executions.jsonl"),
    )

    execution_id = surface.submit(
        "=/flashloan",
        {"prompt": "scan this contract"},
        headers={
            "X-Bastet-Experiment": "exp-override",
            "X-Bastet-Subject": "subject-override",
            "X-Bastet-Request": "req-123",
        },
    )

    request = gateway.requests[0]
    assert execution_id
    assert request.request_id != "req-123"
    assert len(request.request_id) == 32
    assert request.experiment_id == "exp-override"
    assert request.subject_id == "subject-override"
    assert request.surface == "n8n"
    assert request.arm == "upstream"
    assert request.stage == "scan"
    assert request.requested_model == AIS3_PINNED_MODEL
    assert request.max_tokens == 3072
    assert request.temperature == 0.0
    assert request.messages == (
        {"role": "system", "content": "registry system prompt"},
        {"role": "user", "content": "scan this contract"},
    )


@pytest.mark.parametrize("body", [[], {"prompt": ""}, {"prompt": "   "}])
def test_n8n_submit_rejects_malformed_request_bodies(tmp_path, body):
    _write_workflow(tmp_path, "flashloan.json", _workflow(name="flashloan"))
    surface = N8NSurface(
        _load_registry(tmp_path),
        _GatewayStub(json.dumps(_valid_report())),
        ExecutionStore(tmp_path / "executions.jsonl"),
    )

    with pytest.raises(ValueError):
        surface.submit("flashloan", body)


@pytest.mark.parametrize(
    "provider_text",
    [
        "not json",
        json.dumps({"output": {"summary": "wrong"}}),
        json.dumps([1]),
    ],
)
def test_n8n_submit_rejects_malformed_provider_output(tmp_path, provider_text):
    _write_workflow(tmp_path, "flashloan.json", _workflow(name="flashloan"))
    surface = N8NSurface(
        _load_registry(tmp_path),
        _GatewayStub(provider_text),
        ExecutionStore(tmp_path / "executions.jsonl"),
    )

    with pytest.raises(ProviderOutputMalformed):
        surface.submit("flashloan", {"prompt": "scan"})


def test_n8n_submit_rejects_unknown_routes(tmp_path):
    _write_workflow(tmp_path, "flashloan.json", _workflow(name="flashloan"))
    surface = N8NSurface(
        _load_registry(tmp_path),
        _GatewayStub(json.dumps(_valid_report())),
        ExecutionStore(tmp_path / "executions.jsonl"),
    )

    with pytest.raises(UnknownWebhookRoute, match="route was not found"):
        surface.submit("unknown", {"prompt": "scan"})


def test_execution_payload_rejects_unknown_execution_ids(tmp_path):
    _write_workflow(tmp_path, "flashloan.json", _workflow(name="flashloan"))
    surface = N8NSurface(
        _load_registry(tmp_path),
        _GatewayStub(json.dumps(_valid_report())),
        ExecutionStore(tmp_path / "executions.jsonl"),
    )

    with pytest.raises(UnknownExecution, match="was not found"):
        surface.execution_payload("missing")


def test_execution_payload_matches_the_exact_upstream_indexing_tree(tmp_path):
    _write_workflow(tmp_path, "flashloan.json", _workflow(name="flashloan"))
    gateway = _GatewayStub(
        json.dumps(
            [
                {
                    "summary": "flashloan issue",
                    "severity": "unknown",
                    "vulnerability_details": {
                        "Function Name": "borrow",
                        "Description": "borrow path is exposed",
                    },
                    "code_snippet": [7, " line "],
                    "recommendation": "add validation",
                }
            ]
        )
    )
    surface = N8NSurface(
        _load_registry(tmp_path),
        gateway,
        ExecutionStore(tmp_path / "executions.jsonl"),
    )

    execution_id = surface.submit("flashloan", {"prompt": "scan"})
    payload = surface.execution_payload(execution_id)
    output = payload["data"]["resultData"]["runData"]["flashloan"][0]["data"]["main"][0][0]["json"]["output"]

    assert payload["finished"] is True
    assert payload["data"]["executionData"]["nodeExecutionStack"] == []
    assert payload["data"]["resultData"]["lastNodeExecuted"] == "flashloan"
    assert output == [
        {
            "summary": "flashloan issue",
            "severity": "high",
            "vulnerability_details": {
                "function_name": "borrow",
                "description": "borrow path is exposed",
            },
            "code_snippet": ["7", "line"],
            "recommendation": "add validation",
        }
    ]


def test_execution_store_redacts_credential_shaped_provider_output(tmp_path):
    _write_workflow(tmp_path, "flashloan.json", _workflow(name="flashloan"))
    fake_key = "sk-" + "execution-store-not-real"
    report = _valid_report()
    report[0]["summary"] = f"provider echoed {fake_key}"
    path = tmp_path / "executions.jsonl"
    surface = N8NSurface(
        _load_registry(tmp_path),
        _GatewayStub(json.dumps(report)),
        ExecutionStore(path),
    )

    execution_id = surface.submit("flashloan", {"prompt": "scan"})
    payload = surface.execution_payload(execution_id)
    blob = path.read_text(encoding="utf-8")

    assert fake_key not in blob
    assert fake_key not in json.dumps(payload)
    assert "[REDACTED:token]" in blob

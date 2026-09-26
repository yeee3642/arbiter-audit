#!/usr/bin/env bash
# Safe launcher for the pinned-model upstream compatibility surface.
#
# This intentionally does not:
#   - run `docker compose down -v`
#   - write API keys or n8n credentials to .env
#   - mutate frozen upstream workflow JSON
#
# The original browser-driven n8n setup remains useful for visual inspection,
# but a fair automated baseline needs one metered gateway below both systems.
set -euo pipefail

PINNED_MODEL="ais3/llama-3.1-8b"
MODEL="${1:-$PINNED_MODEL}"
UPSTREAM_ROOT="${BASTET_UPSTREAM_ROOT:?set BASTET_UPSTREAM_ROOT to a frozen Bastet checkout}"
EXPERIMENT="${BASTET_EXPERIMENT_ID:-phase1-smoke}"
SUBJECT="${BASTET_SUBJECT_ID:-upstream-example}"
PORT="${BASTET_AUTOMATION_PORT:-8765}"
RUN_DIR="${BASTET_AUTOMATION_RUN_DIR:-runs/automation}"

if [[ "$MODEL" != "$PINNED_MODEL" ]]; then
  echo "refusing model '$MODEL'; the fair profile is pinned to $PINNED_MODEL" >&2
  exit 2
fi

args=(
  automation serve
  --workflow-root "$UPSTREAM_ROOT/n8n_workflow"
  --workflow flashloan
  --experiment "$EXPERIMENT"
  --subject "$SUBJECT"
  --host 127.0.0.1
  --port "$PORT"
  --run-dir "$RUN_DIR"
)

MODE="mock"
if [[ "${BASTET_AUTOMATION_LIVE:-0}" == "1" ]]; then
  : "${AIS3_API_KEY:?live mode requires a rotated AIS3_API_KEY in the environment}"
  args+=(--live)
  MODE="live"
fi

echo "starting pinned dual-surface gateway on http://127.0.0.1:$PORT"
echo "mode: $MODE (default is deterministic mock)"
exec bastet-cc "${args[@]}"

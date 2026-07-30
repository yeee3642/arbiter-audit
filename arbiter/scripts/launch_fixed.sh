#!/usr/bin/env bash
# The re-run every headline number needs.
#
# Four harness defects were fixed after the last benchmark, one of them a constructible
# false-positive path in the conservation clause, plus a frame-scoping bug that made a
# quarter of the reference exploits inexpressible. So every recorded number was produced
# by code that no longer exists, and "was this run after the fixes?" is a question with
# only one acceptable answer.
#
# Same evalset, same model, same turn and attempt budget as the recorded strict arm, so
# the fixes are the only difference. Resumable: relaunch with the same run id and
# finished samples are skipped.
#
#   scripts/launch_fixed.sh [run-id]
set -u

RUN_ID="${1:-fixed1}"
source "$HOME/.arbiter_env"
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1

exec python3 cli.py run \
    --evalset evalsets/v4_test.json \
    --model ais3/nemotron-3-ultra-550b \
    --run-id "$RUN_ID" \
    --attempts 2 --max-turns 26 --concurrency 16 --rpm 70

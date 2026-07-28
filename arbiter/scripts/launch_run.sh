#!/usr/bin/env bash
# Launch an ARBITER run over a labelled evaluation set, detached from the ssh session.
#
#   launch_run.sh <run-id> <evalset> <turns> <attempts> <concurrency> <rpm>
set -u

RUN_ID="$1"; EVALSET="$2"; TURNS="$3"; ATTEMPTS="$4"; CONC="$5"; RPM="$6"

export PATH="$HOME/.foundry/bin:$PATH"
: "${AIS3_API_KEY:?set AIS3_API_KEY before launching}"

cd "$HOME/rig/arbiter" || exit 1
LOG="$HOME/${RUN_ID}.log"

setsid python3 cli.py run \
  --evalset "$EVALSET" \
  --model ais3/nemotron-3-ultra-550b \
  --run-id "$RUN_ID" \
  --attempts "$ATTEMPTS" \
  --max-turns "$TURNS" \
  --concurrency "$CONC" \
  --rpm "$RPM" > "$LOG" 2>&1 < /dev/null &

echo "launched $RUN_ID (pid $!) -> $LOG"
